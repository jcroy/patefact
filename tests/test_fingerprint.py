import hashlib
import httpx
from opendir.capture.fingerprint import header_order_hash, template_hash, favicon_sha256
from opendir.capture.fetcher import Fetcher

def test_header_order_hash_ignores_values_not_order():
    a = header_order_hash([("server", "nginx"), ("date", "x")])
    b = header_order_hash([("server", "apache"), ("date", "y")])
    c = header_order_hash([("date", "x"), ("server", "nginx")])
    assert a == b        # same order, different values
    assert a != c        # different order

def test_template_hash_collides_for_same_template_different_files():
    t1 = "<pre><a href='a.zip'>a.zip</a>\n<a href='b.iso'>b.iso</a></pre>"
    t2 = "<pre><a href='x.txt'>x.txt</a>\n<a href='y.bin'>y.bin</a></pre>"
    assert template_hash(t1) == template_hash(t2)

def test_template_hash_differs_for_different_template():
    assert template_hash("<pre>x</pre>") != template_hash("<table>x</table>")

def test_template_hash_ignores_files_dates_sizes_and_count():
    a = (
        "<html><body><h1>Index of /a/</h1><pre>"
        "<a href=\"../\">../</a>\n"
        "<a href=\"one.zip\">one.zip</a>   01-Jan-2020 10:00   100\n"
        "<a href=\"two.txt\">two.txt</a>   02-Jan-2020 11:00   200\n"
        "</pre></body></html>"
    )
    b = (
        "<html><body><h1>Index of /other/</h1><pre>"
        "<a href=\"../\">../</a>\n"
        "<a href=\"alpha.iso\">alpha.iso</a>  09-Sep-2026 23:59   9999999\n"
        "<a href=\"beta.bin\">beta.bin</a>  10-Sep-2026 00:01   42\n"
        "<a href=\"gamma.md\">gamma.md</a>  11-Sep-2026 00:02   7\n"
        "</pre></body></html>"
    )
    assert template_hash(a) == template_hash(b)

def test_template_hash_table_vs_pre_differ():
    table = (
        "<html><body><table><tr><td><a href=\"a.zip\">a.zip</a></td>"
        "<td>100</td></tr></table></body></html>"
    )
    pre = (
        "<html><body><pre><a href=\"a.zip\">a.zip</a>   100\n</pre></body></html>"
    )
    assert template_hash(table) != template_hash(pre)

def test_favicon_sha256_hashes_bytes():
    raw = b"\x00icon-bytes"
    def handler(request):
        assert request.url.path == "/favicon.ico"
        return httpx.Response(200, content=raw)
    f = Fetcher(transport=httpx.MockTransport(handler))
    assert favicon_sha256(f, "http://ex.com/files/") == hashlib.sha256(raw).hexdigest()

def test_favicon_sha256_none_when_missing():
    def handler(request):
        return httpx.Response(404)
    f = Fetcher(transport=httpx.MockTransport(handler))
    assert favicon_sha256(f, "http://ex.com/") is None
