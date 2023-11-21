"""nurllib.parse
A clean-slate rewrite of urllib.parse
Shooting for compatibility with RFCs 3986 and 3987
"""

import copy
import dataclasses
import re

from typing import Iterator, Iterable, Self, Callable, Any, Sequence

# I have no problem with any of these, so I'm fine copying them from urllib.parse:
from urllib.parse import (
    urlencode,
    non_hierarchical,
    scheme_chars,
    parse_qs,
    parse_qsl,
    quote,
    quote_from_bytes,
    quote_plus,
    unquote_to_bytes,
    uses_fragment,
    uses_netloc,
    uses_params,
    uses_query,
    uses_relative,
)  # pylint: disable=unused-import

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
_PCT_ENCODED: str = rf"%{_HEXDIG}{_HEXDIG}"

# sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
_SUB_DELIMS: str = r"[!$&'()*+,;=]"

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
_SEGMENT: str = rf"{_PCHAR}*"

# isegment = *ipchar
_ISEGMENT: str = rf"{_IPCHAR}*"

# segment-nz = 1*pchar
_SEGMENT_NZ: str = rf"{_PCHAR}+"

# isegment-nz = 1*ipchar
_ISEGMENT_NZ: str = rf"{_IPCHAR}+"

# segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
_SEGMENT_NZ_NC: str = rf"(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|@)+"

# isegment-nz-nc = 1*( iunreserved / pct-encoded / sub-delims / "@" )
_ISEGMENT_NZ_NC: str = rf"(?:{_IUNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS}|@)+"

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
_IPV4ADDRESS: str = rf"{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}"

# h16 = 1*4HEXDIG
_H16: str = rf"(?:{_HEXDIG}{{1,4}})"

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
            rf"(?:(?:{_H16}:){{0,3}}{_H16})?::(?:{_H16}:){_LS32}",
            rf"(?:(?:{_H16}:){{0,4}}{_H16})?::{_LS32}",
            rf"(?:(?:{_H16}:){{0,5}}{_H16})?::{_H16}",
            rf"(?:(?:{_H16}:){{0,6}}{_H16})?::",
        )
    )
    + ")"
)

# ZoneID = 1*( unreserved / pct-encoded )
_ZONEID = rf"(?:{_UNRESERVED}|{_PCT_ENCODED})+"

# IPv6addrz = IPv6address "%25" ZoneID
_IPV6ADDRZ = rf"{_IPV6ADDRESS}%25{_ZONEID}"

# IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
_IPVFUTURE: str = rf"v{_HEXDIG}+\.(?:{_UNRESERVED}|{_SUB_DELIMS}|:)+"

# IP-literal = "[" ( IPv6address / IPvFuture ) "]"
# (IRIs don't support zoneinfo, so we need both versions of this rule)
_IIP_LITERAL: str = rf"\[(?:{_IPV6ADDRESS}|{_IPVFUTURE})\]"

# IP-literal = "[" ( IPv6address / IPv6addrz / IPvFuture  ) "]"
_IP_LITERAL: str = rf"\[(?:{_IPV6ADDRESS}|{_IPV6ADDRZ}|{_IPVFUTURE})\]"

# reg-name = *( unreserved / pct-encoded / sub-delims )
_REG_NAME: str = rf"(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS})*"

# ireg-name = *( iunreserved / pct-encoded / sub-delims )
_IREG_NAME: str = rf"(?:{_IUNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMS})*"

# host = IP-literal / IPv4address / reg-name
_HOST: str = rf"(?P<host>{_IP_LITERAL}|{_IPV4ADDRESS}|{_REG_NAME})"

# ihost = IP-literal / IPv4address / ireg-name
_IHOST: str = rf"(?P<host>{_IIP_LITERAL}|{_IPV4ADDRESS}|{_IREG_NAME})"

# port = *DIGIT
_PORT: str = rf"(?P<port>{_DIGIT}*)"

# authority = [ userinfo "@" ] host [ ":" port ]
_AUTHORITY: str = rf"(?:{_USERINFO}@)?{_HOST}(?::{_PORT})?"

# iauthority = [ iuserinfo "@" ] ihost [ ":" port ]
_IAUTHORITY: str = rf"(?:{_IUSERINFO}@)?{_IHOST}(?::{_PORT})?"

# hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
_HIER_PART: str = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_ROOTLESS}|{_PATH_EMPTY})"

# ihier-part = "//" iauthority ipath-abempty / ipath-absolute / ipath-rootless / ipath-empty
_IHIER_PART: str = rf"(?://{_IAUTHORITY}{_IPATH_ABEMPTY}|{_IPATH_ABSOLUTE}|{_IPATH_ROOTLESS}|{_IPATH_EMPTY})"

# relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty
_RELATIVE_PART: str = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_NOSCHEME}|{_PATH_EMPTY})"

# irelative-part = "//" iauthority ipath-abempty / ipath-absolute / ipath-noscheme / ipath-empty
_IRELATIVE_PART: str = (
    rf"(?://{_IAUTHORITY}{_IPATH_ABEMPTY}|{_IPATH_ABSOLUTE}|{_IPATH_NOSCHEME}|{_IPATH_EMPTY})"
)

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
class NURL:
    """A class to hold an IRI-Reference. You should not instantiate this directly. Instead use one of the parse_* functions."""

    raw_scheme: str | None
    raw_userinfo: str | None
    raw_host: str | None
    raw_port: str | None
    raw_path: str
    raw_query: str | None
    raw_fragment: str | None

    @property
    def scheme(self: Self):  # Not typed for back-compat
        return self.raw_scheme

    @property
    def userinfo(self: Self) -> str | None:
        return self.raw_userinfo

    @property
    def host(self: Self) -> str | None:
        return self.raw_host

    @property
    def port(self: Self) -> int | None:
        if self.raw_port is not None and len(self.raw_port) > 0:
            return int(self.raw_port, base=10)
        return None

    @property
    def path(self: Self):  # Not typed for back-compat
        return self.raw_path

    @property
    def query(self: Self):  # Not typed for back-compat
        return self.raw_query

    @property
    def fragment(self: Self):  # Not typed for back-compat
        return self.raw_fragment

    def serialize(self: Self) -> str:
        """Direct translation of RFC 3986 section 5.3"""
        result: str = ""
        if self.raw_scheme is not None:
            result += f"{self.raw_scheme}:"
        if self.authority is not None:
            result += f"//{self.authority}"
        result += self.raw_path
        if self.raw_query is not None:
            result += f"?{self.raw_query}"
        if self.raw_fragment is not None:
            result += f"#{self.raw_fragment}"
        return result

    @property
    def authority(self: Self) -> str | None:
        """userinfo@host:port"""
        if self.raw_host is None:
            return None
        result: str = ""
        if self.raw_userinfo is not None:
            result += f"{self.raw_userinfo}@"
        result += self.raw_host
        if self.raw_port is not None:
            result += f":{self.raw_port}"
        return result

    def join(self: Self, r: Self, strict: bool = True) -> Self:
        """Implementation of the "Transform References" algorithm from RFC 3986 section 5.2.2"""

        scheme: str | None
        userinfo: str | None
        host: str | None
        port: str | None
        path: str
        query: str | None
        fragment: str | None

        # This is a direct translation of the pseudocode in the RFC.
        # It could be made prettier, but I'm leaving it like this because
        # it's easy to check against the RFC.
        r_scheme: str | None = r.raw_scheme
        if not strict and r.raw_scheme == self.raw_scheme:
            r_scheme = None
        if r_scheme is not None:
            scheme = r_scheme
            userinfo = r.raw_userinfo
            host = r.raw_host
            port = r.raw_port
            path = _remove_dot_segments(r.raw_path)
            query = r.raw_query
        else:
            if r.authority is not None:
                userinfo = r.raw_userinfo
                host = r.raw_host
                port = r.raw_port
                path = _remove_dot_segments(r.raw_path)
                query = r.raw_query
            else:
                if len(r.raw_path) == 0:
                    path = self.raw_path
                    if r.raw_query is not None:
                        query = r.raw_query
                    else:
                        query = self.raw_query
                else:
                    if r.raw_path.startswith("/"):
                        path = _remove_dot_segments(r.raw_path)
                    else:
                        path = _merge_paths(self, r)
                        path = _remove_dot_segments(path)
                    query = r.raw_query
                userinfo = self.raw_userinfo
                host = self.raw_host
                port = self.raw_port
            scheme = self.raw_scheme
        fragment = r.raw_fragment

        return self.__class__(
            raw_scheme=scheme,
            raw_userinfo=userinfo,
            raw_host=host,
            raw_port=port,
            raw_path=path,
            raw_query=query,
            raw_fragment=fragment,
        )


def _capitalize_percent_encodings(string: str) -> str:
    """Returns string with all percent-encoded sequences expressed in capital letters.
    e.g. _capitalize_percent_encodings("example%2ecom") == "example%2Ecom"
    """
    # Capitalize each percent-encoded sequence that uses lowercase letters.
    # Does not change length of string.
    for m in re.finditer(rf"%(?:[a-f]{_HEXDIG}|{_HEXDIG}[a-f])", string):
        string = string[: m.start()] + string[m.start() : m.end()].upper() + string[m.end() :]
    return string


def _parse(data: str, pattern: re.Pattern[str] | str, path_kinds: Iterable[str]) -> NURL:
    m: re.Match[str] | None = re.match(pattern, data)
    if m is None:
        raise ValueError("parse failed")

    # Because relative references don't have a scheme group in their regexes,
    # this requires an extra check.
    scheme: str | None = m["scheme"] if "scheme" in m.groupdict() else None
    if scheme is not None:
        scheme = scheme.lower()

    userinfo: str | None = m["userinfo"]
    if userinfo is not None:
        userinfo = _capitalize_percent_encodings(userinfo)

    host: str | None = m["host"]
    if host is not None:
        if host.isascii():
            host = host.lower()
        host = _capitalize_percent_encodings(host)

    port: str | None = m["port"]
    if port:
        # Get rid of leading 0s.
        port = str(int(port))

    query: str | None = m["query"]
    if query is not None:
        query = _capitalize_percent_encodings(query)

    fragment: str | None = m["fragment"]
    if fragment is not None:
        fragment = _capitalize_percent_encodings(fragment)

    return NURL(
        raw_scheme=scheme,
        raw_userinfo=userinfo,
        raw_host=host,
        raw_port=port,
        raw_path=_capitalize_percent_encodings(m[next(pk for pk in path_kinds if m[pk] is not None)]),
        raw_query=query,
        raw_fragment=fragment,
    )


_URI_PATH_KINDS: tuple[str, ...] = ("path_abempty", "path_absolute", "path_empty", "path_rootless")


def parse_uri(data: str) -> NURL:
    """RFC 3986-compliant URI parser.
    If you want to parse a URL that contains only ASCII characters (e.g. "http://example.org/path?query#fragment"), this is the function to use.
    """
    return _parse(data, _URI_PAT, _URI_PATH_KINDS)


def parse_iri(data: str) -> NURL:
    """RFC 3987-compliant IRI parser.
    If you want to parse a URL that contains non-ASCII characters (e.g. "https://en.wiktionary.org/wiki/Ῥόδος?query#fragment"), this is the function to use.
    """
    return _parse(data, _IRI_PAT, _URI_PATH_KINDS)


_RELATIVE_REF_PATH_KINDS: tuple[str, ...] = ("path_abempty", "path_absolute", "path_empty", "path_noscheme")


def parse_relative_ref(data: str) -> NURL:
    """RFC 3986-compliant relative-ref parser.
    If you want to parse a relative reference that contains only ASCII characters (e.g. "//example.org/path?query#fragment"), this is the function to use.
    """
    return _parse(data, _RELATIVE_REF_PAT, _RELATIVE_REF_PATH_KINDS)


def parse_irelative_ref(data: str) -> NURL:
    """RFC 3987-compliant irelative-ref parser.
    If you want to parse a relative reference that contains non-ASCII characters (e.g. "//en.wiktionary.org/wiki/Ῥόδος?query#fragment"), this is the function to use.
    """
    return _parse(data, _IRELATIVE_REF_PAT, _RELATIVE_REF_PATH_KINDS)


def parse_uri_reference(data: str) -> NURL:
    """RFC 3986-compliant URI-Reference parser.
    Only use this when you don't know whether you want to parse a URI or a relative-ref.
    """
    try:
        return parse_uri(data)
    except ValueError:
        pass
    try:
        return parse_relative_ref(data)
    except ValueError:
        pass
    raise ValueError("failed to parse URI-Reference")


def parse_iri_reference(data: str) -> NURL:
    """RFC 3987-compliant IRI-Reference parser.
    Only use this when you don't know whether you want to parse an IRI or an irelative-ref.
    """
    try:
        return parse_iri(data)
    except ValueError:
        pass
    try:
        return parse_irelative_ref(data)
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
            path = f"/{path[len('/./') :]}"
        elif path.startswith("/../") or path == "/..":
            path = f"/{path[len('/../') :]}"
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


def _merge_paths(base: NURL, r: NURL) -> str:
    """Implementation of the "merge" routine defined in RFC 3986 section 5.2.3"""
    if base.raw_host is not None and len(base.raw_path) == 0:
        return f"/{r.raw_path}"
    dirname, slash, _ = base.raw_path.rpartition("/")
    return dirname + slash + r.raw_path


############################################################################################################
# ------------ Everything below here is crud that we need for compatibility with urllib.parse ------------ #
############################################################################################################


_DEFAULT_ENCODING: str = "ascii"


def _squish_fragment(ref: NURL) -> NURL:
    result: NURL = copy.copy(ref)
    if result.raw_fragment is None:
        return result
    if result.raw_query is not None:
        result.raw_query += f"#{result.raw_fragment}"
    else:
        result.raw_path += f"#{result.raw_fragment}"
    result.raw_fragment = None
    return result


def _remove_fragment(ref: NURL) -> NURL:
    result: NURL = copy.copy(ref)
    result.raw_fragment = None
    return result


class Result(NURL):
    def __init__(self: Self, fields: Iterable[str], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fields: tuple[str, ...] = tuple(fields)

    def __len__(self: Self) -> int:
        return len(self._fields)

    def __iter__(self: Self) -> Iterator[str]:
        return iter(map(lambda field: getattr(self, field), self._fields))

    def __repr__(self: Self) -> str:
        return f"{self.__class__.__name__}({', '.join(field + '=' + repr(value) for field, value in zip(self._fields, self))})"

    def __eq__(self: Self, other) -> bool:
        return tuple(self) == tuple(other)

    def __getitem__(self: Self, idx: int):
        return list(self)[idx]

    @property
    def username(self: Self):
        if self.userinfo is None:
            return None
        return self.userinfo.partition(":")[0]

    @property
    def password(self: Self):
        if self.userinfo is None:
            return None
        _, colon, password = self.userinfo.partition(":")
        if len(colon) == 0:
            return None
        return password

    @property
    def hostname(self: Self):
        if self.host is None:
            return None
        if self.host.startswith("["):
            return self.host[1:-1]
        return self.host

    @property
    def query(self: Self):
        return self.raw_query if self.raw_query is not None else ""

    @property
    def fragment(self: Self):
        return self.raw_fragment if self.raw_fragment is not None else ""

    @property
    def netloc(self: Self):
        return self.authority if self.authority is not None else ""

    @property
    def scheme(self: Self):
        return self.raw_scheme if self.raw_scheme is not None else ""

    def geturl(self: Self):
        return self.serialize()


def _encode_if_not_none(s: str, encoding: str) -> bytes | None:
    if s is None:
        return None
    return s.encode(encoding)


class ResultBytes(Result):
    def __init__(self: Self, fields: Iterable[str], encoding: str, *args, **kwargs) -> None:
        super().__init__(fields, *args, **kwargs)
        self._encoding = encoding

    def geturl(self: Self) -> bytes:
        return super().geturl().encode(self._encoding)

    @property
    def scheme(self: Self) -> bytes:
        return super().scheme.encode(self._encoding)

    @property
    def netloc(self: Self) -> bytes:
        return super().netloc.encode(self._encoding)

    @property
    def fragment(self: Self) -> bytes:
        return super().fragment.encode(self._encoding)

    @property
    def query(self: Self) -> bytes:
        return super().query.encode(self._encoding)

    @property
    def hostname(self: Self) -> bytes | None:
        return _encode_if_not_none(super().hostname, self._encoding)

    @property
    def username(self: Self) -> bytes | None:
        return _encode_if_not_none(super().username, self._encoding)

    @property
    def password(self: Self) -> bytes | None:
        return _encode_if_not_none(super().password, self._encoding)

    @property
    def path(self: Self) -> bytes:
        return super().path.encode(self._encoding)


class SplitResultBytes(ResultBytes):
    _fields: tuple[str, ...] = ("scheme", "netloc", "path", "query", "fragment")

    def __init__(self: Self, encoding: str, *args, **kwargs) -> None:
        super().__init__(SplitResultBytes._fields, encoding, *args, **kwargs)


class SplitResult(Result):
    _fields: tuple[str, ...] = SplitResultBytes._fields

    def __init__(self: Self, *args, **kwargs) -> None:
        super().__init__(SplitResult._fields, *args, **kwargs)

    def encode(self: Self, encoding: str) -> SplitResultBytes:
        return SplitResultBytes(
            encoding,
            self.raw_scheme,
            self.raw_userinfo,
            self.raw_host,
            self.raw_port,
            self.raw_path,
            self.raw_query,
            self.raw_fragment,
        )


class DefragResultBytes(ResultBytes):
    _fields: tuple[str, ...] = ("url", "fragment")

    def __init__(self: Self, encoding: str, *args, **kwargs) -> None:
        super().__init__(DefragResultBytes._fields, encoding, *args, **kwargs)

    @property
    def url(self: Self) -> bytes:
        if self.raw_fragment is None:
            return self.geturl()
        return self.geturl()[: -len(f"#{self.raw_fragment}")]


class DefragResult(Result):
    _fields: tuple[str, ...] = DefragResultBytes._fields

    def __init__(self: Self, *args, **kwargs) -> None:
        super().__init__(DefragResult._fields, *args, **kwargs)

    @property
    def url(self: Self) -> str:
        if self.raw_fragment is None:
            return self.geturl()
        return self.geturl()[: -len(f"#{self.raw_fragment}")]

    def encode(self: Self, encoding: str) -> DefragResultBytes:
        return DefragResultBytes(
            encoding,
            self.raw_scheme,
            self.raw_userinfo,
            self.raw_host,
            self.raw_port,
            self.raw_path,
            self.raw_query,
            self.raw_fragment,
        )


def _extract_params(path: str) -> str | None:
    last_seg: str = path.rpartition("/")[2]
    _, semicolon, params = last_seg.partition(";")
    if len(semicolon) == 0:
        return None
    return params


class ParseResultBytes(ResultBytes):
    _fields: tuple[str, ...] = ("scheme", "netloc", "path", "params", "query", "fragment")

    def __init__(self: Self, encoding: str, *args, **kwargs) -> None:
        super().__init__(ParseResultBytes._fields, encoding, *args, **kwargs)
        self.raw_params: str | None = _extract_params(self.raw_path)

    @property
    def params(self: Self) -> bytes:
        return self.raw_params.encode(self._encoding) if self.raw_params is not None else b""

    @property
    def path(self: Self) -> bytes:
        return (
            self.raw_path[: -len(f";{self.raw_params}")] if self.raw_params is not None else self.raw_path
        ).encode(self._encoding)

    def geturl(self: Self) -> bytes:
        """Translation of RFC 3986 section 5.3 with added params support"""
        result: str = ""
        if self.raw_scheme is not None:
            result += f"{self.raw_scheme}:"
        if self.authority is not None:
            result += f"//{self.authority}"
        result += self.path.decode(self._encoding)
        if self.raw_params is not None:
            result += f";{self.raw_params}"
        if self.raw_query is not None:
            result += f"?{self.raw_query}"
        if self.raw_fragment is not None:
            result += f"#{self.raw_fragment}"
        return result.encode(self._encoding)


class ParseResult(Result):
    _fields: tuple[str, ...] = ParseResultBytes._fields

    def __init__(self: Self, *args, **kwargs) -> None:
        super().__init__(ParseResult._fields, *args, **kwargs)
        self.raw_params: str | None = _extract_params(self.raw_path)

    @property
    def params(self: Self) -> str:
        return self.raw_params if self.raw_params is not None else ""

    @property
    def path(self: Self) -> str:
        if self.raw_params is not None:
            return self.raw_path[: -len(f";{self.raw_params}")]
        return self.raw_path

    def geturl(self: Any) -> str:
        """Translation of RFC 3986 section 5.3 with added params support"""
        result: str = ""
        if self.raw_scheme is not None:
            result += f"{self.raw_scheme}:"
        if self.authority is not None:
            result += f"//{self.authority}"
        result += self.path
        if self.raw_params is not None:
            result += f";{self.raw_params}"
        if self.raw_query is not None:
            result += f"?{self.raw_query}"
        if self.raw_fragment is not None:
            result += f"#{self.raw_fragment}"
        return result

    def encode(self: Self, encoding: str) -> ParseResultBytes:
        return ParseResultBytes(
            encoding,
            self.raw_scheme,
            self.raw_userinfo,
            self.raw_host,
            self.raw_port,
            self.raw_path,
            self.raw_query,
            self.raw_fragment,
        )


def _nurlparse(url: str | bytes, scheme: str | bytes | None = None, allow_fragments: bool = True) -> NURL:
    if scheme is not None:
        if (isinstance(scheme, bytes) and not isinstance(url, bytes)) or (
            isinstance(scheme, str) and not isinstance(url, str)
        ):
            raise TypeError("Cannot mix str and bytes")
        if isinstance(scheme, bytes):
            scheme = scheme.decode(_DEFAULT_ENCODING)

        scheme = re.sub(r"[\r\n\t]", "", scheme)
        if len(scheme) == 0:  # For compatibility with the old default value of scheme=""
            scheme = None
        elif not re.fullmatch(_SCHEME, scheme):
            raise ValueError("Invalid scheme")

    if isinstance(url, bytes):
        url = url.decode(_DEFAULT_ENCODING)
    url = re.sub(r"[\r\n\t]", "", url)

    is_ascii: bool = url.isascii()
    url_parser: Callable[[str], NURL] = parse_uri if is_ascii else parse_iri
    ref_parser: Callable[[str], NURL] = parse_relative_ref if is_ascii else parse_irelative_ref

    result: NURL | None = None
    try:
        result = url_parser(url)
        if not allow_fragments:
            result = _squish_fragment(result)
        return result
    except ValueError:
        pass
    try:
        result = ref_parser(url)
        if scheme is not None:
            result.raw_scheme = scheme
        if not allow_fragments:
            result = _squish_fragment(result)
        return result
    except ValueError:
        pass
    raise ValueError("failed to parse URL")


def urlparse(
    url: str | bytes, scheme: str | bytes | None = None, allow_fragments: bool = True
) -> ParseResult | ParseResultBytes:
    """IRI-Reference parser designed to be backwards-compatible with urllib.parse.urlparse."""
    if scheme == "":
        scheme = None
    is_bytes: bool = isinstance(url, bytes)
    nurl: NURL = _nurlparse(url, scheme=scheme, allow_fragments=allow_fragments)
    result: ParseResult = ParseResult(
        raw_scheme=nurl.raw_scheme,
        raw_userinfo=nurl.raw_userinfo,
        raw_host=nurl.raw_host,
        raw_port=nurl.raw_port,
        raw_path=nurl.raw_path,
        raw_query=nurl.raw_query,
        raw_fragment=nurl.raw_fragment,
    )
    return result.encode(_DEFAULT_ENCODING) if is_bytes else result


def urlsplit(
    url: str | bytes, scheme: str | bytes | None = None, allow_fragments: bool = True
) -> SplitResult | SplitResultBytes:
    if scheme == "":
        scheme = None
    is_bytes: bool = isinstance(url, bytes)
    nurl: NURL = _nurlparse(url, scheme=scheme, allow_fragments=allow_fragments)
    result: SplitResult = SplitResult(
        raw_scheme=nurl.raw_scheme,
        raw_userinfo=nurl.raw_userinfo,
        raw_host=nurl.raw_host,
        raw_port=nurl.raw_port,
        raw_path=nurl.raw_path,
        raw_query=nurl.raw_query,
        raw_fragment=nurl.raw_fragment,
    )
    return result.encode(_DEFAULT_ENCODING) if is_bytes else result


def urlunparse(components: Sequence[str] | Sequence[bytes]) -> str | bytes:
    is_bytes: bool = isinstance(components[0], bytes)
    if not any(all(isinstance(c, t) for c in components) for t in (str, bytes)):
        raise TypeError("Cannot mix str and bytes")
    scheme, authority, path, params, query, fragment = (
        c.decode(_DEFAULT_ENCODING) if isinstance(c, bytes) else c for c in components
    )
    result: str = ""
    if len(scheme) > 0:
        result += f"{scheme}:"
    if len(authority) > 0:
        result += f"//{authority}"
    result += path
    if len(params) > 0:
        result += f";{params}"
    if len(query) > 0:
        result += f"?{query}"
    if len(fragment) > 0:
        result += f"#{fragment}"
    return result.encode(_DEFAULT_ENCODING) if is_bytes else result


def urlunsplit(components: Sequence[str] | Sequence[bytes]) -> str | bytes:
    is_bytes: bool = isinstance(components[0], bytes)
    if not any(all(isinstance(c, t) for c in components) for t in (str, bytes)):
        raise TypeError("Cannot mix str and bytes")
    scheme, authority, path, query, fragment = (
        c.decode(_DEFAULT_ENCODING) if isinstance(c, bytes) else c for c in components
    )
    result: str = ""
    if len(scheme) > 0:
        result += f"{scheme}:"
    if len(authority) > 0:
        result += f"//{authority}"
    result += path
    if len(query) > 0:
        result += f"?{query}"
    if len(fragment) > 0:
        result += f"#{fragment}"
    return result.encode(_DEFAULT_ENCODING) if is_bytes else result


def urljoin(base: str | bytes, url: str | bytes, allow_fragments: bool = True) -> str | bytes:
    if (isinstance(base, bytes) and not isinstance(url, bytes)) or (
        isinstance(base, str) and not isinstance(url, str)
    ):
        raise TypeError("Cannot mix str and bytes")
    result: str = (
        _nurlparse(base, allow_fragments=allow_fragments)
        .join(_nurlparse(url, allow_fragments=allow_fragments), strict=False)
        .serialize()
    )
    return result.encode(_DEFAULT_ENCODING) if isinstance(base, bytes) else result


def urldefrag(url: str | bytes) -> DefragResult | DefragResultBytes:
    is_bytes: bool = isinstance(url, bytes)
    nurl: NURL = _nurlparse(url)
    result: DefragResult = DefragResult(
        raw_scheme=nurl.raw_scheme,
        raw_userinfo=nurl.raw_userinfo,
        raw_host=nurl.raw_host,
        raw_port=nurl.raw_port,
        raw_path=nurl.raw_path,
        raw_query=nurl.raw_query,
        raw_fragment=nurl.raw_fragment,
    )
    return result.encode(_DEFAULT_ENCODING) if is_bytes else result
