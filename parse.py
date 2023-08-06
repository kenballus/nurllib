"""nurllib.parse
urllib.parse is unmaintainable, so this is a clean-slate rewrite of urllib.parse
I am shooting for RFC 3986 compatibility.

Differences from urllib:
    - Removal of all deprecated components.
    - Addition of uriparse and relativerefparse. Use of these should be encouraged over urlparse.

To do:
    - Add support for allow_fragment
    - Add support for bytes
    - Support RFC 3987
    - Implement __setitem__
    - Add parse_qs, parse_qsl, urldefrag?
    - Support RFC 6874??
"""

import dataclasses
import re
import warnings

from typing import Iterator

__all__ = [
    "ParseResult",
    "SplitResult",
    "urlparse",
    "urlunparse",
    "urlsplit",
    "urlunsplit",
    "urljoin",
]


# I have less of a problem with these functions, so I'm cool importing them from urllib:
from urllib.parse import (
    quote,
    quote_from_bytes,
    quote_plus,
    unquote,
    unquote_plus,
    unquote_to_bytes,
    urlencode,
)

# Each of these ABNF rules is from RFC 3986 or 5234.

# ALPHA = %x41-5A / %x61-7A
_ALPHA: str = r"[A-Za-z]"

# DIGIT =  %x30-39
_DIGIT: str = r"[0-9]"

# HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
_HEXDIG: str = rf"(?:{_DIGIT}|[A-Fa-f])"

# unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
_UNRESERVED: str = rf"(?:{_ALPHA}|{_DIGIT}|[-._~])"

# pct-encoded = "%" HEXDIG HEXDIG
_PCT_ENCODED: str = rf"(?:%{_HEXDIG}{_HEXDIG})"

# sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
_SUB_DELIMS: str = r"(?:[!$&'()*+,;=])"

# pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
_PCHAR: str = rf"(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|[:@])"

# query = *( pchar / "/" / "?" )
_QUERY: str = rf"(?P<query>(?:{_PCHAR}|[/?])*)"

# fragment = *( pchar / "/" / "?" )
_FRAGMENT: str = rf"(?P<fragment>(?:{_PCHAR}|[/?])*)"

# scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME: str = rf"(?P<scheme>{_ALPHA}(?:{_ALPHA}|{_DIGIT}|[+\-.])*)"

# segment = *pchar
_SEGMENT: str = rf"{_PCHAR}*"

# segment-nz = 1*pchar
_SEGMENT_NZ: str = rf"{_PCHAR}+"

# segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
_SEGMENT_NZ_NC: str = rf"(?:(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|@)+)"

# path-absolute = "/" [ segment-nz *( "/" segment ) ]
_PATH_ABSOLUTE: str = rf"(?P<path_absolute>/(?:{_SEGMENT_NZ}(?:/{_SEGMENT})*)?)"

# path-empty = 0<pchar>
_PATH_EMPTY: str = r"(?P<path_empty>)"

# path-rootless = segment-nz *( "/" segment )
_PATH_ROOTLESS: str = rf"(?P<path_rootless>{_SEGMENT_NZ}(?:/{_SEGMENT})*)"

# path-abempty = *( "/" segment )
_PATH_ABEMPTY: str = rf"(?P<path_abempty>(?:/{_SEGMENT})*)"

# path-noscheme = segment-nz-nc *( "/" segment )
_PATH_NOSCHEME: str = rf"(?P<path_noscheme>{_SEGMENT_NZ_NC}(?:/{_SEGMENT})*)"

# userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
_USERINFO: str = rf"(?P<userinfo>(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|:)*)"

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

# IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
_IP_LITERAL: str = rf"(?:\[(?:{_IPV6ADDRESS}|{_IPVFUTURE})\])"

# reg-name = *( unreserved / pct-encoded / sub-delims )
_REG_NAME: str = rf"(?:(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS})*)"

# host = IP-literal / IPv4address / reg-name
_HOST: str = rf"(?P<host>{_IP_LITERAL}|{_IPV4ADDRESS}|{_REG_NAME})"

# port = *DIGIT
_PORT: str = rf"(?P<port>{_DIGIT}*)"

# authority = [ userinfo "@" ] host [ ":" port ]
_AUTHORITY: str = rf"(?:(?:{_USERINFO}@)?{_HOST}(?::{_PORT})?)"

# hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
_HIER_PART: str = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_ROOTLESS}|{_PATH_EMPTY})"

# URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
_URI: str = rf"\A{_SCHEME}:{_HIER_PART}(?:\?{_QUERY})?(?:#{_FRAGMENT})?\Z"
_URI_PAT: re.Pattern[str] = re.compile(_URI)

# relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty
_RELATIVE_PART: str = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_NOSCHEME}|{_PATH_EMPTY})"

# relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
_RELATIVE_REF: str = rf"\A{_RELATIVE_PART}(?:\?{_QUERY})?(?:#{_FRAGMENT})?\Z"
_RELATIVE_REF_PAT: re.Pattern[str] = re.compile(_RELATIVE_REF)

@dataclasses.dataclass
class URIReference:
    """A class to hold a URI reference.
    Counterpart to urllib's ParseResult and ParseResultBytes.
    """

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

def uriparse(url: str) -> URIReference:
    """RFC 3986-compliant URI parser."""
    m: re.Match[str] | None = re.match(_URI_PAT, url)
    if m is None:
        raise ValueError("failed to parse URI")
    return URIReference(
        scheme=m["scheme"],
        userinfo=m["userinfo"],
        host=m["host"],
        port=m["port"],
        path=m[next(filter(lambda path_kind: m[path_kind] is not None, ("path_abempty", "path_absolute", "path_empty", "path_rootless")))],
        query=m["query"],
        fragment=m["fragment"],
    )


def relativerefparse(url: str) -> URIReference:
    """RFC 3986-compliant relative-ref parser."""
    path_kinds: list[str] = []
    m: re.Match[str] | None = re.match(_RELATIVE_REF_PAT, url)
    if m is None:
        raise ValueError("failed to parse relative-ref")
    return URIReference(
        scheme=None,
        userinfo=m["userinfo"],
        host=m["host"],
        port=m["port"],
        path=m[next(filter(lambda path_kind: m[path_kind] is not None, ("path_abempty", "path_absolute", "path_empty", "path_noscheme")))],
        query=m["query"],
        fragment=m["fragment"],
    )


def urireferenceparse(url: str) -> URIReference:
    """RFC 3986-compliant URI-Reference parser.
    Only use this when you don't know whether you want to parse a URI or a relative-ref.
    """
    try:
        return uriparse(url)
    except ValueError:
        pass
    try:
        return relativerefparse(url)
    except ValueError:
        pass
    raise ValueError("failed to parse URI-Reference")

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


def _merge_paths(base: URIReference, r: URIReference) -> str:
    """Implementation of the "merge" routine defined in RFC 3986 section 5.2.3"""
    if base.host is not None and len(base.path) == 0:
        return "/" + r.path
    dirname, slash, _ = base.path.rpartition("/")
    return dirname + slash + r.path

def urijoin(base: str | URIReference, r: str | URIReference) -> URIReference:
    """Implementation of the "Transform References" algorithm from RFC 3986 section 5.2.2"""
    if isinstance(base, str):
        base = uriparse(base)
    if isinstance(r, str):
        r = urireferenceparse(r)

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
        authority = r.authority
        path = _remove_dot_segments(r.path)
        query = r.query
    else:
        if r.authority is not None:
            authority = r.authority
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
            authority = base.authority
        scheme = base.scheme
    fragment = r.fragment

    return URIReference(
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

class ParseResult(URIReference):
    """Deprecated. A subclass of URIReference with a focus on compatibility with urllib."""

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
    def from_urireference(cls, uriref: URIReference):
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

def urlparse(url: str, scheme: str = "", allow_fragments: bool = True) -> ParseResult:
    warnings.warn("urlparse is deprecated. Use uriparse, relativerefparse, or urireferenceparse instead.", DeprecationWarning, stacklevel=2)
    if len(scheme) > 0 and re.match(rf"\A{_SCHEME}\Z", scheme) is None:
        raise ValueError("failed to parse scheme")
    try:
        return ParseResult.from_urireference(uriparse(url))
    except ValueError:
        pass
    try:
        rr: URIReference = relativerefparse(url)
        if len(scheme) > 0:
            rr.scheme = scheme
        return ParseResult.from_urireference(rr)
    except ValueError:
        pass
    raise ValueError("failed to parse URL")


class SplitResult(ParseResult):
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
    return SplitResult.from_urireference(urlparse(url, scheme))
