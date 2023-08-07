"""nurllib.parse
urllib.parse is unmaintainable, so this is a clean-slate rewrite of urllib.parse
I am shooting for compatibility with RFCs 3986, 3987, and 6874.

Differences from urllib:
    - Removal of all deprecated components.
    - Addition of parse_uri and parse_relative_ref. Use of these should be encouraged over urlparse.

To do:
    - Add support for bytes
"""

import dataclasses
import re
import warnings

from typing import Iterator, Iterable

# Each of these ABNF rules is from RFC 3986, 3987, 6874, or 5234.

# ALPHA = %x41-5A / %x61-7A
_ALPHA: str = r"[A-Za-z]"

# DIGIT = %x30-39
_DIGIT: str = r"[0-9]"

# HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
_HEXDIG: str = rf"(?:{_DIGIT}|[A-Fa-f])"

# ucschar = %xA0-D7FF / %xF900-FDCF / %xFDF0-FFEF
#         / %x10000-1FFFD / %x20000-2FFFD / %x30000-3FFFD
#         / %x40000-4FFFD / %x50000-5FFFD / %x60000-6FFFD
#         / %x70000-7FFFD / %x80000-8FFFD / %x90000-9FFFD
#         / %xA0000-AFFFD / %xB0000-BFFFD / %xC0000-CFFFD
#         / %xD0000-DFFFD / %xE1000-EFFFD
_UCSCHAR: str = "[\xa0-\ud7ff\uf900-\ufdcf\ufdf0-\uffef\U00010000-\U0001FFFD\U00020000-\U0002FFFD\U00030000-\U0003FFFD\U00040000-\U0004FFFD\U00050000-\U0005FFFD\U00060000-\U0006FFFD\U00070000-\U0007FFFD\U00080000-\U0008FFFD\U00090000-\U0009FFFD\U000A0000-\U000AFFFD\U000B0000-\U000BFFFD\U000C0000-\U000CFFFD\U000D0000-\U000DFFFD\U000E0000-\U000EFFFD]"

# iprivate = %xE000-F8FF / %xF0000-FFFFD / %x100000-10FFFD
_IPRIVATE: str = "[\ue000-\uf8ff\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]"

# unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
_UNRESERVED: str = rf"(?:{_ALPHA}|{_DIGIT}|[-._~])"

# iunreserved = ALPHA / DIGIT / "-" / "." / "_" / "~" / ucschar
_IUNRESERVED: str = rf"(?:{_ALPHA}|{_DIGIT}|[-._~]|{_UCSCHAR})"

# pct-encoded = "%" HEXDIG HEXDIG
_PCT_ENCODED: str = rf"(?:%{_HEXDIG}{_HEXDIG})"

# sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
_SUB_DELIMS: str = r"(?:[!$&'()*+,;=])"

# pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
_PCHAR: str = rf"(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|[:@])"

# ipchar = iunreserved / pct-encoded / sub-delims / ":" / "@"
_IPCHAR: str = rf"(?:{_IUNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|[:@])"

# query = *( pchar / "/" / "?" )
_QUERY: str = rf"(?P<query>(?:{_PCHAR}|[/?])*)"

# iquery = *( ipchar / iprivate / "/" / "?" )
_IQUERY: str = rf"(?P<query>(?:{_IPCHAR}|{_IPRIVATE}|[/?])*)"

# fragment = *( pchar / "/" / "?" )
_FRAGMENT: str = rf"(?P<fragment>(?:{_PCHAR}|[/?])*)"

# ifragment = *( ipchar / "/" / "?" )
_IFRAGMENT: str = rf"(?P<fragment>(?:{_IPCHAR}|[/?])*)"

# scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME: str = rf"(?P<scheme>{_ALPHA}(?:{_ALPHA}|{_DIGIT}|[+\-.])*)"

# segment = *pchar
_SEGMENT: str = f"{_PCHAR}*"

# isegment = *ipchar
_ISEGMENT: str = f"{_IPCHAR}*"

# segment-nz = 1*pchar
_SEGMENT_NZ: str = f"{_PCHAR}+"

# isegment-nz = 1*ipchar
_ISEGMENT_NZ: str = f"{_IPCHAR}+"

# segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
_SEGMENT_NZ_NC: str = rf"(?:(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|@)+)"

# isegment-nz-nc = 1*( iunreserved / pct-encoded / sub-delims / "@" )
_ISEGMENT_NZ_NC: str = rf"(?:(?:{_IUNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|@)+)"

# path-absolute = "/" [ segment-nz *( "/" segment ) ]
_PATH_ABSOLUTE: str = rf"(?P<path_absolute>/(?:{_SEGMENT_NZ}(?:/{_SEGMENT})*)?)"

# ipath-absolute = "/" [ isegment-nz *( "/" isegment ) ]
_IPATH_ABSOLUTE: str = rf"(?P<path_absolute>/(?:{_ISEGMENT_NZ}(?:/{_ISEGMENT})*)?)"

# path-empty = 0<pchar>
_PATH_EMPTY: str = r"(?P<path_empty>)"

# ipath-empty = 0<ipchar>
_IPATH_EMPTY: str = r"(?P<path_empty>)"

# path-rootless = segment-nz *( "/" segment )
_PATH_ROOTLESS: str = rf"(?P<path_rootless>{_SEGMENT_NZ}(?:/{_SEGMENT})*)"

# ipath-rootless = isegment-nz *( "/" isegment )
_IPATH_ROOTLESS: str = rf"(?P<path_rootless>{_ISEGMENT_NZ}(?:/{_ISEGMENT})*)"

# path-abempty = *( "/" segment )
_PATH_ABEMPTY: str = rf"(?P<path_abempty>(?:/{_SEGMENT})*)"

# ipath-abempty = *( "/" isegment )
_IPATH_ABEMPTY: str = rf"(?P<path_abempty>(?:/{_ISEGMENT})*)"

# path-noscheme = segment-nz-nc *( "/" segment )
_PATH_NOSCHEME: str = rf"(?P<path_noscheme>{_SEGMENT_NZ_NC}(?:/{_SEGMENT})*)"

# ipath-noscheme = isegment-nz-nc *( "/" isegment )
_IPATH_NOSCHEME: str = rf"(?P<path_noscheme>{_ISEGMENT_NZ_NC}(?:/{_ISEGMENT})*)"

# userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
_USERINFO: str = rf"(?P<userinfo>(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|:)*)"

# iuserinfo = *( iunreserved / pct-encoded / sub-delims / ":" )
_IUSERINFO: str = rf"(?P<userinfo>(?:{_IUNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|:)*)"

# dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
_DEC_OCTET: str = rf"(?:{_DIGIT}|[1-9]{_DIGIT}|1{_DIGIT}{{2}}|2[0-4]{_DIGIT}|25[0-5])"

# IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
_IPV4ADDRESS: str = rf"(?:{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET})"

# h16 = 1*4HEXDIG
_H16: str = r"(?:[0-9A-F]{1,4})"

# ls32 = ( h16 ":" h16 ) / IPv4address
_LS32: str = rf"(?:{_H16}:{_H16}|{_IPV4ADDRESS})"

# IPv6address =                                      6( h16 ":" ) ls32
#                       /                       "::" 5( h16 ":" ) ls32
#                       / [               h16 ] "::" 4( h16 ":" ) ls32
#                       / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
#                       / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
#                       / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
#                       / [ *4( h16 ":" ) h16 ] "::"              ls32
#                       / [ *5( h16 ":" ) h16 ] "::"              h16
#                       / [ *6( h16 ":" ) h16 ] "::"
_IPV6ADDRESS: str = (
    "(?:"
    + r"|".join(
        (
                                           rf"(?:{_H16}:){{6}}{_LS32}",
                                         rf"::(?:{_H16}:){{5}}{_LS32}",
                              rf"(?:{_H16})?::(?:{_H16}:){{4}}{_LS32}",
            rf"(?:(?:{_H16}:){{0,1}}{_H16})?::(?:{_H16}:){{3}}{_LS32}",
            rf"(?:(?:{_H16}:){{0,2}}{_H16})?::(?:{_H16}:){{2}}{_LS32}",
            rf"(?:(?:{_H16}:){{0,3}}{_H16})?::(?:{_H16}:){{1}}{_LS32}",
            rf"(?:(?:{_H16}:){{0,4}}{_H16})?::{_LS32}",
            rf"(?:(?:{_H16}:){{0,5}}{_H16})?::{_H16}",
            rf"(?:(?:{_H16}:){{0,6}}{_H16})?::",
        )
    )
    + ")"
)

# IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
_IPVFUTURE: str = rf"(?:v{_HEXDIG}+\.(?:{_UNRESERVED}|{_SUB_DELIMS}|:)+)"

# ZoneID = 1*( unreserved / pct-encoded )
_ZONEID: str = rf"(?:{_UNRESERVED}|{_PCT_ENCODED})+"

# IPv6addrz = IPv6address "%25" ZoneID
_IPV6ADDRZ: str = rf"{_IPV6ADDRESS}%25{_ZONEID}"

# IP-literal = "[" ( IPv6address / IPv6addrz / IPvFuture ) "]"
_IP_LITERAL: str = rf"(?:\[(?:{_IPV6ADDRESS}|{_IPV6ADDRZ}|{_IPVFUTURE})\])"

# reg-name = *( unreserved / pct-encoded / sub-delims )
_REG_NAME: str = rf"(?:(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS})*)"

# ireg-name = *( iunreserved / pct-encoded / sub-delims )
_IREG_NAME: str = rf"(?:(?:{_IUNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS})*)"

# host = IP-literal / IPv4address / reg-name
_HOST: str = rf"(?P<host>{_IP_LITERAL}|{_IPV4ADDRESS}|{_REG_NAME})"

# ihost = IP-literal / IPv4address / ireg-name
_IHOST: str = rf"(?P<host>{_IP_LITERAL}|{_IPV4ADDRESS}|{_IREG_NAME})"

# port = *DIGIT
_PORT: str = rf"(?P<port>{_DIGIT}*)"

# authority = [ userinfo "@" ] host [ ":" port ]
_AUTHORITY: str = rf"(?:(?:{_USERINFO}@)?{_HOST}(?::{_PORT})?)"

# iauthority = [ iuserinfo "@" ] ihost [ ":" port ]
_IAUTHORITY: str = rf"(?:(?:{_IUSERINFO}@)?{_IHOST}(?::{_PORT})?)"

# hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
_HIER_PART: str = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_ROOTLESS}|{_PATH_EMPTY})"

# ihier-part = "//" iauthority ipath-abempty / ipath-absolute / ipath-rootless / ipath-empty
_IHIER_PART: str = rf"(?://{_IAUTHORITY}{_IPATH_ABEMPTY}|{_IPATH_ABSOLUTE}|{_IPATH_ROOTLESS}|{_IPATH_EMPTY})"

# relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty
_RELATIVE_PART: str = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_NOSCHEME}|{_PATH_EMPTY})"

# irelative-part = "//" iauthority ipath-abempty / ipath-absolute / ipath-noscheme / ipath-empty
_IRELATIVE_PART: str = rf"(?://{_IAUTHORITY}{_IPATH_ABEMPTY}|{_IPATH_ABSOLUTE}|{_IPATH_NOSCHEME}|{_IPATH_EMPTY})"

# URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
_URI: str = rf"\A{_SCHEME}:{_HIER_PART}(?:\?{_QUERY})?(?:#{_FRAGMENT})?\Z"
_URI_PAT: re.Pattern[str] = re.compile(_URI)

# IRI = scheme ":" ihier-part [ "?" iquery] [ "#" ifragment ]
_IRI: str = rf"\A{_SCHEME}:{_IHIER_PART}(?:\?{_IQUERY})?(?:#{_IFRAGMENT})?\Z"
_IRI_PAT: re.Pattern[str] = re.compile(_IRI)

# relative-ref = relative-part [ "?" query ] [ "#" fragment ]
_RELATIVE_REF: str = rf"\A{_RELATIVE_PART}(?:\?{_QUERY})?(?:#{_FRAGMENT})?\Z"
_RELATIVE_REF_PAT: re.Pattern[str] = re.compile(_RELATIVE_REF)

# irelative-ref = irelative-part [ "?" iquery ] [ "#" ifragment ]
_IRELATIVE_REF: str = rf"\A{_IRELATIVE_PART}(?:\?{_IQUERY})?(?:#{_IFRAGMENT})?\Z"
_IRELATIVE_REF_PAT: re.Pattern[str] = re.compile(_IRELATIVE_REF)

@dataclasses.dataclass
class IRIReference:
    """A class to hold an IRI-Reference."""

    scheme: str | None
    userinfo: str | None
    host: str | None
    port: int | None
    path: str
    query: str | None
    fragment: str | None

    def __init__(
        self,
        scheme: str | None,
        userinfo: str | None,
        host: str | None,
        port: str | int | None,
        path: str,
        query: str | None,
        fragment: str | None,
    ):
        self.scheme = scheme.lower() if scheme else None
        self.userinfo = _capitalize_percent_encodings(userinfo) if userinfo else None
        self.host = _capitalize_percent_encodings(host.lower()) if host else None
        if isinstance(port, str):
            self.port = int(port)
        else:
            if isinstance(port, int) and port < 0:
                raise ValueError("negative ports are invalid")
            self.port = port
        self.path = _capitalize_percent_encodings(path)
        self.query = _capitalize_percent_encodings(query) if query else None
        self.fragment = _capitalize_percent_encodings(fragment) if fragment else None

    def __str__(self) -> str:
        """Direct translation of RFC 3986 section 5.3"""
        result: str = ""
        if self.scheme is not None:
            result += self.scheme + ":"
        if self.authority is not None:
            result += "//" + self.authority
        result += self.path
        if self.query is not None:
            result += "?" + self.query
        if self.fragment is not None:
            result += "#" + self.fragment
        return result

    @property
    def authority(self) -> str | None:
        """userinfo@host:port"""
        if self.host is None:
            return None
        result: str = ""
        if self.userinfo is not None:
            result += self.userinfo + "@"
        result += self.host
        if self.port is not None:
            result += ":" + str(self.port)
        return result

def _capitalize_percent_encodings(string: str) -> str:
    """Returns string with all percent-encoded bytes expressed in capital letters.
    e.g. _capitalize_percent_encodings("example%2ecom") == "example%2Ecom"
    """
    for m in re.finditer(rf"%(?:[a-f]{_HEXDIG}|{_HEXDIG}[a-f])", string):
        string = (
            string[: m.start()]
            + string[m.start() : m.end()].upper()
            + string[m.end() :]
        )
    return string

def parse_uri(uri: str) -> IRIReference:
    """RFC 3986-compliant URI parser."""
    m: re.Match[str] | None = re.match(_URI_PAT, uri)
    if m is None:
        raise ValueError("failed to parse URI")
    return IRIReference(
        scheme=m["scheme"],
        userinfo=m["userinfo"],
        host=m["host"],
        port=m["port"],
        path=m[next(path_kind for path_kind in ("path_abempty", "path_absolute", "path_empty", "path_rootless") if m[path_kind] is not None)],
        query=m["query"],
        fragment=m["fragment"],
    )


def parse_iri(iri: str) -> IRIReference:
    """RFC 3987-compliant IRI parser."""
    m: re.Match[str] | None = re.match(_IRI_PAT, iri)
    if m is None:
        raise ValueError("failed to parse IRI")
    return IRIReference(
        scheme=m["scheme"],
        userinfo=m["userinfo"],
        host=m["host"],
        port=m["port"],
        path=m[next(path_kind for path_kind in ("path_abempty", "path_absolute", "path_empty", "path_rootless") if m[path_kind] is not None)],
        query=m["query"],
        fragment=m["fragment"],
    )


def parse_relative_ref(url: str) -> IRIReference:
    """RFC 3986-compliant relative-ref parser."""
    m: re.Match[str] | None = re.match(_RELATIVE_REF_PAT, url)
    if m is None:
        raise ValueError("failed to parse relative-ref")
    return IRIReference(
        scheme=None,
        userinfo=m["userinfo"],
        host=m["host"],
        port=m["port"],
        path=m[next(path_kind for path_kind in ("path_abempty", "path_absolute", "path_empty", "path_noscheme") if m[path_kind] is not None)],
        query=m["query"],
        fragment=m["fragment"],
    )


def parse_irelative_ref(irelative_ref: str) -> IRIReference:
    """RFC 3987-compliant irelative-ref parser."""
    m: re.Match[str] | None = re.match(_IRELATIVE_REF_PAT, irelative_ref)
    if m is None:
        raise ValueError("failed to parse irelative-ref")
    return IRIReference(
        scheme=None,
        userinfo=m["userinfo"],
        host=m["host"],
        port=m["port"],
        path=m[next(path_kind for path_kind in ("path_abempty", "path_absolute", "path_empty", "path_noscheme") if m[path_kind] is not None)],
        query=m["query"],
        fragment=m["fragment"],
    )


def parse_uri_reference(uri_reference: str) -> IRIReference:
    """RFC 3986-compliant URI-Reference parser.
    Only use this when you don't know whether you want to parse a URI or a relative-ref.
    """
    try:
        return parse_uri(uri_reference)
    except ValueError:
        pass
    try:
        return parse_relative_ref(uri_reference)
    except ValueError:
        pass
    raise ValueError("failed to parse URI-Reference")


def parse_iri_reference(iri_reference: str) -> IRIReference:
    """RFC 3987-compliant IRI-Reference parser.
    Only use this when you don't know whether you want to parse a IRI or an irelative-ref.
    """
    try:
        return parse_iri(iri_reference)
    except ValueError:
        pass
    try:
        return parse_irelative_ref(iri_reference)
    except ValueError:
        pass
    raise ValueError("failed to parse IRI-Reference")

def _remove_dot_segments(path: str) -> str:
    """Implementation of the "remove_dot_segments" routine from RFC 3986 section 5.2.4"""
    result: str = ""
    while len(path) > 0:
        if path.startswith("./") or path.startswith("../"):
            _, _, path = path.partition("/")
        elif path.startswith("/./") or path == "/.":
            path = "/" + path[len("/./"):]
        elif path.startswith("/../") or path == "/..":
            path = "/" + path[len("/../"):]
            result, _, _ = result.rpartition("/")
        elif path in (".", ".."):
            path = ""
        else:
            if path.startswith("/"):
                _, _, path = path.partition("/")
                result += "/"
            first_seg, slash, rest = path.partition("/")
            path = slash + rest
            result += first_seg
    return result


def _merge_paths(base: IRIReference, r: IRIReference) -> str:
    """Implementation of the "merge" routine defined in RFC 3986 section 5.2.3"""
    if base.host is not None and len(base.path) == 0:
        return "/" + r.path
    dirname, slash, _ = base.path.rpartition("/")
    return dirname + slash + r.path

def join_uri(base: IRIReference, r: IRIReference) -> IRIReference:
    """Implementation of the "Transform References" algorithm from RFC 3986 section 5.2.2"""

    scheme: str | None
    userinfo: str | None
    host: str | None
    port: int | None
    path: str
    query: str | None
    fragment: str | None

    # This is a direct translation of the pseudocode in the RFC.
    # It could be made prettier, but I'm leaving it like this because
    # it's easy to check that it's the same as the RFC.
    if r.scheme is not None:
        scheme = r.scheme
        userinfo = r.userinfo
        host = r.host
        port = r.port
        path = _remove_dot_segments(r.path)
        query = r.query
    else:
        if r.authority is not None:
            userinfo = r.userinfo
            host = r.host
            port = r.port
            path = _remove_dot_segments(r.path)
            query = r.query
        else:
            if len(r.path) == 0:
                path = base.path
                if r.query is not None:
                    query = r.query
                else:
                    query = base.query
            else:
                if r.path.startswith("/"):
                    path = _remove_dot_segments(r.path)
                else:
                    path = _merge_paths(base, r)
                    path = _remove_dot_segments(path)
                query = r.query
            userinfo = base.userinfo
            host = base.host
            port = base.port
        scheme = base.scheme
    fragment = r.fragment

    return IRIReference(
        scheme=scheme,
        userinfo=userinfo,
        host=host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
    )


############################################################################################################
#------------- Everything below here is crud that we need for compatibility with urllib.parse -------------#
############################################################################################################

class ParseResult(IRIReference):
    """Deprecated. A subclass of IRIReference with a focus on compatibility with urllib."""

    def __getitem__(self, idx: int) -> str | None:
        """urllib compatibility function. The old ParseResult was a namedtuple, so this is here to maintain compatibility with it."""
        return list(self)[idx]

    def __iter__(self) -> Iterator[str]:
        """urllib compatibility function. The old ParseResult was a namedtuple, so this is here to maintain compatibility with it."""
        return iter(
            (
                self.scheme if self.scheme else "",
                self.netloc if self.netloc else "",
                self.path if self.path else "",
                self.params if self.params else "",
                self.query if self.query else "",
                self.fragment if self.fragment else "",
            )
        )

    @classmethod
    def from_urireference(cls, uriref: IRIReference):
        """Constructs a ParseResult (or child class) from a IRIReference"""
        return cls(
            scheme=uriref.scheme,
            userinfo=uriref.userinfo,
            host=uriref.host,
            port=uriref.port,
            path=uriref.path,
            query=uriref.query,
            fragment=uriref.fragment,
        )

    def geturl(self) -> str:
        """Returns URL in string form."""
        return str(self)

    @property
    def hostname(self) -> str:
        """Returns self.host."""
        return self.host if self.host is not None else ""

    @property
    def netloc(self) -> str:
        """Returns username@host:port separated by a colon."""
        result: str = ""
        if self.userinfo is not None:
            result += self.userinfo + "@"
        if self.host is not None:
            result += self.host
        if self.port is not None:
            result += ":" + str(self.port)
        return result

    @property
    def params(self) -> str:
        """Returns everything after the first semicolon in the last path segment."""
        _, _, last_seg = self.path.rpartition("/")
        _, _, result = last_seg.rpartition(";")
        return result

    @property
    def password(self) -> str | None:
        """Returns everything after the first colon in the userinfo."""
        if self.userinfo is not None:
            colon_idx: int = self.userinfo.find(":")
            if colon_idx == -1:
                return None
            return self.userinfo[colon_idx + 1 :]
        return None

    @property
    def username(self) -> str:
        """Returns everything before the first colon in the userinfo."""
        if self.userinfo is not None:
            result, _, _ = self.userinfo.partition(":")
            return result
        return ""

    def squish_fragment(self) -> None:
        """Appends the fragment into the query if there is one, and the path if there isn't."""
        if self.fragment is None:
            return
        if self.query is not None:
            self.query += self.fragment
        else:
            self.path += self.fragment
        self.fragment = None


def urlparse(url: str, scheme: str = "", allow_fragments: bool = True) -> ParseResult:
    """URI-Reference parser designed to be backwards-compatible with urllib.parse.urlparse."""
    warnings.warn("urlparse is deprecated. Use parse_uri, parse_relative_ref, or parse_uri_reference instead.", DeprecationWarning, stacklevel=2)
    if len(scheme) > 0 and re.match(rf"\A{_SCHEME}\Z", scheme) is None:
        raise ValueError("failed to parse scheme")

    result: ParseResult
    try:
        result = ParseResult.from_urireference(parse_uri(url))
    except ValueError:
        try:
            rr: IRIReference = parse_relative_ref(url)
            if len(scheme) > 0:
                rr.scheme = scheme
            result = ParseResult.from_urireference(rr)
            if not allow_fragments:
                result.squish_fragment()
        except ValueError:
            raise ValueError("failed to parse URL")
    if not allow_fragments:
        result.squish_fragment()
    return result

def urlunparse(components: Iterable[str]) -> str:
    """Deprecated."""
    warnings.warn("urlunparse is deprecated. Use IRIReference.__str__ instead.", DeprecationWarning, stacklevel=2)
    scheme, authority, path, params, query, fragment = components
    result: str = ""
    if len(scheme) > 0:
        result += scheme + ":"
    if len(authority) > 0:
        result += "//" + authority
    result += path
    if len(params) > 0:
        result += ";" + params
    if len(query) > 0:
        result += "?" + query
    if len(fragment) > 0:
        result += "#" + fragment
    return result

class SplitResult(ParseResult):
    """The return type of urlsplit, which has 5 members instead of ParseResult's 6."""
    def __getitem__(self, idx: int) -> str | None:
        """The old SplitResult was a namedtuple, so this is here to maintain compatibility with it."""
        return list(self)[idx]

    def __iter__(self) -> Iterator[str]:
        """The old SplitResult was a namedtuple, so this is here to maintain compatibility with it."""
        return iter(
            (
                self.scheme if self.scheme else "",
                self.netloc if self.netloc else "",
                self.path if self.path else "",
                self.query if self.query else "",
                self.fragment if self.fragment else "",
            )
        )


def urlsplit(url: str, scheme: str = "", allow_fragments: bool = True) -> SplitResult:
    """Deprecated."""
    warnings.warn("urlsplit is deprecated. Use parse_uri, parse_relative_ref, or parse_uri_reference instead.", DeprecationWarning, stacklevel=2)
    result: SplitResult = SplitResult.from_urireference(urlparse(url, scheme))
    if not allow_fragments:
        result.squish_fragment()
    return result

def urlunsplit(components: Iterable[str]) -> str:
    """Deprecated."""
    warnings.warn("urlunsplit is deprecated. Use IRIReference.__str__ instead.", DeprecationWarning, stacklevel=2)
    scheme, authority, path, query, fragment = components
    result: str = ""
    if len(scheme) > 0:
        result += scheme + ":"
    if len(authority) > 0:
        result += "//" + authority
    result += path
    if len(query) > 0:
        result += "?" + query
    if len(fragment) > 0:
        result += "#" + fragment
    return result
