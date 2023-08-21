# Delete anything lying around
rm -f test_urlparse.py
# Grab a fresh copy of the tests
wget https://raw.githubusercontent.com/python/cpython/13104f3b7412dce9bf7cfd09bf2d6dad1f3cc2ed/Lib/test/test_urlparse.py
# Rename the module
sed -i 's/import urllib\.parse/import parse as parse_module/g' test_urlparse.py
sed -i 's/urllib\.parse/parse_module/g' test_urlparse.py

# Delete main for the time being
sed -i 's/unittest\.main()//g' test_urlparse.py

# Because we don't implement any deprecated components.
printf '    del DeprecationTest' >> test_urlparse.py
# Because Quoter is deprecated.
printf ', UrlParseTestCase.test_Quoter_repr' >> test_urlparse.py
# Because we error at parse time during port parsing.
printf ', UrlParseTestCase.test_attributes_bad_port' >> test_urlparse.py
printf ', UrlParseTestCase.test_port_casting_failure_message' >> test_urlparse.py
# Because ':' can't appear in segment-nz-nc, bad scheme should always result in parse failure.
printf ', UrlParseTestCase.test_attributes_bad_scheme' >> test_urlparse.py
# Because __all__ is changing.
printf ', UrlParseTestCase.test_all' >> test_urlparse.py
# Because we don't have _encoded_counterpart and _decoded_counterpart anymore.
sed -i 's/def _check_result_type(self, str_type):/def _check_result_type(self, str_type):\n        return/g' test_urlparse.py
# Because we use the RFC 6874 syntax for scoped IPv6.
printf ', UrlParseTestCase.test_urlsplit_scoped_IPv6' >> test_urlparse.py
# Because urlsplit no longer strips junk from the end of URLs.
printf ', UrlParseTestCase.test_urlsplit_strip_url' >> test_urlparse.py
# Because we don't have clear_cache (it's undocumented).
printf ', UrlParseTestCase.test_clear_cache_for_code_coverage' >> test_urlparse.py
# Because we these things are all either deprecated or undocumented.
printf ', Utility_Tests' >> test_urlparse.py
# Because we don't normalize IRIs. (The RFC says that's the responsibility of the IRI producer.)
printf ', UrlParseTestCase.test_urlsplit_normalization' >> test_urlparse.py

# Put main back
printf '\n    unittest.main()\n' >> test_urlparse.py
