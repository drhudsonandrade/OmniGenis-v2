"""Native bounded MCID-to-ParentTree linkage for exact generated PDFs.

The existing guarded page/ParentTree reference inspector must pass first.
This checks only *parsed* BDC/EMC marker linkage, not all graphics, glyphs,
reading order, structure semantics, historical streams or PDF/UA compliance.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reporting import _pdf_page_tags_worker as page_tags
from reporting._pdf_object_graph_worker import (
    CPU_SECONDS, IDENTITY_FIELDS, MAX_DOCUMENT_PAGES, MAX_PDF_BYTES,
    MAX_DEPTH, MAX_VISITS, MEMORY_BYTES, OPEN_FILES, PARSER_VERSION,
    PROTOCOL_VERSION, RESULT_BYTES, WALL_SECONDS, _read_request,
    _validate_identity, _limits, _lifetime,
)
from reporting._pdf_process_sandbox import enforce_pdf_landlock, enforce_pdf_network_filter
from reporting._pdf_render_worker import _write_bytes

PROFILE_ID="generated-pdf-mcid-parenttree-v1"
POLICY_ID="page-mcid-parenttree-consistency-v1"
STATUS="PAGE_MCID_PARENTTREE_INSPECTED"
LANGUAGE="en-US"
MAX_DECODED_BYTES=8*1024*1024


def _native_marked_ops(content, *, maximum: int) -> set[int]:
    """Parse the supported direct-MCID/Artifact marker profile with finite nesting."""
    from pypdf.generic import DictionaryObject, NameObject, NumberObject
    seen: set[int]=set()
    stack: list[int | None]=[]
    for args,operator in content.operations:
        if operator==b"BDC":
            if (len(args)!=2 or type(args[0]) is not NameObject
                    or args[0]!="/Span"
                    or type(args[1]) is not DictionaryObject
                    or set(args[1])!={"/MCID"}):
                raise ValueError("unsupported BDC marker properties")
            number=args[1]["/MCID"]
            if (type(number) is not NumberObject or not 0<=number<MAX_VISITS
                    or number in seen):
                raise ValueError("invalid or duplicate page MCID")
            seen.add(int(number))
            stack.append(int(number))
        elif operator==b"BMC":
            if (len(args)!=1 or type(args[0]) is not NameObject
                    or args[0]!="/Artifact"):
                raise ValueError("unsupported bare marked sequence")
            stack.append(None)
        elif operator==b"EMC":
            if args or not stack:
                raise ValueError("unbalanced marked-content end")
            stack.pop()
        if len(stack)>MAX_DEPTH or len(seen)>maximum:
            raise ValueError("marked-content budget exceeded")
    if stack:
        raise ValueError("unclosed marked-content sequence")
    return seen


def _inspect(pdf: bytes, identity: dict) -> dict:
    """Inspect complete physical-page *parsed* marker numbers and exact parent slots."""
    _validate_identity(identity)
    if (type(pdf) is not bytes or not pdf.startswith(b"%PDF-1.7")
            or len(pdf)>MAX_PDF_BYTES
            or hashlib.sha256(pdf).hexdigest()!=identity["pdf_sha256"]
            or version("pypdf")!=PARSER_VERSION):
        raise ValueError("MCID input/parser identity")
    if page_tags.PARSER_VERSION!=PARSER_VERSION:
        raise ValueError("page tag dependency mismatch")
    prerequisite=page_tags._inspect(pdf,identity)
    if (prerequisite["status"]!=page_tags.STATUS
            or prerequisite["tagged_pages"]!=identity["page_count"]
            or prerequisite["parent_tree_entries"]!=identity["page_count"]
            or prerequisite["language"]!=LANGUAGE):
        raise ValueError("page tag prerequisite rejected")
    from pypdf import PdfReader
    from pypdf.generic import (ArrayObject, ContentStream, DictionaryObject,
                               IndirectObject, NumberObject)
    reader=PdfReader(BytesIO(pdf),strict=True)
    if reader.is_encrypted or len(reader.pages)!=identity["page_count"]:
        raise ValueError("MCID page identity mismatch")
    struct=reader.root_object["/StructTreeRoot"].get_object()
    parent_tree=struct["/ParentTree"].get_object()
    nums=parent_tree["/Nums"]
    if (type(nums) is not ArrayObject
            or len(nums)!=2*identity["page_count"]):
        raise ValueError("MCID parent number tree mismatch")
    mapping={}
    for i in range(0,len(nums),2):
        key,values=nums[i],nums[i+1]
        if (type(key) is not NumberObject or type(values) is not ArrayObject
                or int(key) in mapping or not values):
            raise ValueError("MCID parent map invalid")
        mapping[int(key)]=values
    decoded_total=0
    visit_total=0
    count=0
    for page in reader.pages:
        key=page.get("/StructParents")
        if type(key) is not NumberObject or int(key) not in mapping:
            raise ValueError("MCID page key invalid")
        values=mapping[int(key)]
        contents=page.get_contents()
        if contents is None:
            raise ValueError("MCID page content missing")
        decoded=contents.get_data()
        if type(decoded) is not bytes:
            raise ValueError("MCID decoded content nonbytes")
        decoded_total+=len(decoded)
        if decoded_total>MAX_DECODED_BYTES:
            raise ValueError("MCID decoded content budget exceeded")
        stream=ContentStream(contents,reader)
        visit_total+=len(stream.operations)
        if visit_total>MAX_VISITS:
            raise ValueError("MCID operation budget exceeded")
        seen=_native_marked_ops(stream,maximum=MAX_VISITS)
        if not seen or len(values)!=len(seen) or seen!=set(range(len(values))):
            raise ValueError("MCID-to-parent index gaps or orphans")
        for index,ref in enumerate(values):
            if type(ref) is not IndirectObject:
                raise ValueError("MCID parent entry nonindirect")
            element=ref.get_object()
            if type(element) is not DictionaryObject:
                raise ValueError("MCID structural entry malformed")
            item=element.get("/K")
            if type(item) is NumberObject:
                kids=[int(item)]
            elif type(item) is ArrayObject and item:
                if any(type(k) is not NumberObject for k in item):
                    raise ValueError("MCID structure child wrong type")
                kids=[int(k) for k in item]
            else:
                raise ValueError("MCID unsupported structural child")
            if (len(kids)!=len(set(kids)) or index not in kids
                    or any(k<0 or k>=len(values) for k in kids)):
                raise ValueError("MCID structural child reference mismatch")
            for k in kids:
                peer=values[k]
                if not page_tags._same_ref(ref,peer):
                    raise ValueError("MCID structure cross-slot link mismatch")
        count+=len(seen)
    if count<identity["page_count"] or count>MAX_VISITS:
        raise ValueError("MCID total count invalid")
    return {"status":STATUS,"matched_mcids":count,
            "decoded_bytes":decoded_total,"inspected_pages":identity["page_count"]}


def main(argv: list[str] | None=None) -> int:
    """Fail closed if any guard, parser, integrity or structural check fails."""
    argv=sys.argv if argv is None else argv
    if (sys.platform!="linux" or type(argv) is not list or len(argv)!=4
            or any(type(v) is not str or not v.isascii() or not v.isdecimal()
                   or len(v)>10 for v in argv[1:])):
        return 64
    try:
        first,second,parent=map(int,argv[1:])
        if (any(str(n)!=s for n,s in zip((first,second,parent),argv[1:],strict=True))
                or min(first,second)<3 or first==second
                or not 2<=parent<=2147483647):
            return 64
        infos=[os.fstat(fd) for fd in (first,second)]
        if (any(not stat.S_ISREG(v.st_mode) or v.st_nlink!=0
                or v.st_uid!=os.geteuid() for v in infos)
                or (infos[0].st_dev,infos[0].st_ino)==(infos[1].st_dev,infos[1].st_ino)
                or infos[1].st_size):
            return 64
        limits=_limits()
        _lifetime(parent)
        enforce_pdf_landlock(Path(__file__))
        enforce_pdf_network_filter()
        identity,pdf=_read_request(first)
        payload={"protocol_version":PROTOCOL_VERSION,"profile_id":PROFILE_ID,
                 "policy_id":POLICY_ID,"parser_version":PARSER_VERSION,
                 "identity":identity,"limits":limits,
                 "inspection":_inspect(pdf,identity)}
        encoded=json.dumps(payload,sort_keys=True,separators=(",",":"),
                           ensure_ascii=True,allow_nan=False).encode("ascii")
        if not 0<len(encoded)<=RESULT_BYTES:
            return 70
        _write_bytes(second,encoded)
    except Exception:
        return 70
    return 0

if __name__=="__main__":
    raise SystemExit(main())
