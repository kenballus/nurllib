# nurllib.parse

This is a rewrite of large portions of urllib.parse.

## What's changed:
- All the parsing is done with regexes, strictly compliant to RFCs 3986, 3987, and 6874.
- Performance is about 2x worse (with caching enabled)
- All deprecated and undocumented components are removed.
- There are new functions that allow you to parse only URIs, IRIs, relative-refs, or irelative-refs.
- NFKC normalization is no longer applied before parsing. The standard recommends that it is the IRI producer's responsibility to do this, not ours.
- Hosts and schemes are normalized to lowercase.
- Percent-encoded bytes are normalized to uppercase.
- `urlsplit` no longer strips garbage bytes from the beginning and end of its input.
- The Result types are no longer able to be constructed explicitly.
- URLs are now joined according to the procedure from RFC 3986. This involves more path normalization than urllib.parse uses.
- Leading 0s are now stripped from port numbers.

## What's exactly the same:
- `urlencode`
- `non_hierarchical`
- `scheme_chars`
- `parse_qs`
- `parse_qsl`
- `quote`
- `quote_from_bytes`
- `quote_plus`
- `unquote_to_bytes`
- `uses_fragment`
- `uses_netloc`
- `uses_params`
- `uses_query`
- `uses_relative`

## What's functionally the same:
Everything else, hopefully
