import json
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from ai_guard.server import Handler


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_page(self):
        with urllib.request.urlopen(self.url) as r:
            self.assertIn("AI Guard", r.read().decode("utf-8"))

    def test_authenticated_request_and_spoofed_identity(self):
        body = json.dumps({"scenario": "knowledge", "query": "读取财务", "tool": "read_document",
                           "arguments": {"document_id": "finance-a"}, "roles": ["finance"],
                           "user": "admin", "tenant": "b"}).encode()
        request = urllib.request.Request(self.url + "/api/run", data=body,
                                         headers={"Authorization": "Bearer demo-alice"})
        with urllib.request.urlopen(request) as r:
            self.assertTrue(json.load(r)["blocked"])

    def test_unauthenticated(self):
        request = urllib.request.Request(self.url + "/api/run", data=b"{}")
        with self.assertRaises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request)
        self.assertEqual(exc.exception.code, 401)
