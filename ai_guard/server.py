import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .core import Guard, Identity

ROOT = Path(__file__).resolve().parent.parent
GUARD = Guard(audit_path=ROOT / "runtime" / "audit.jsonl")
# Demo credentials only. Production must use verified sessions/OIDC claims.
SESSIONS = {
    "demo-alice": Identity("alice", "a", ("employee",)),
    "demo-bob": Identity("bob", "a", ("employee",)),
    "demo-finance": Identity("finance", "a", ("finance",)),
    "demo-analyst": Identity("analyst", "a", ("analyst",)),
    "demo-admin": Identity("admin", "a", ("admin",)),
    "demo-company-b": Identity("user-b", "b", ("employee",)),
}


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/scenarios":
            return self.respond(200, GUARD.policies)
        if self.path != "/":
            return self.respond(404, {"error": "不存在"})
        body = (ROOT / "web" / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        user = SESSIONS.get(token)
        if not user:
            return self.respond(401, {"error": "请使用有效的演示身份"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                return self.respond(413, {"error": "请求大小无效"})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("请求必须是对象")
            if self.path == "/api/run":
                if not isinstance(data.get("query"), str) or not isinstance(data.get("scenario"), str):
                    raise ValueError("缺少场景或问题")
                if data.get("arguments") is not None and not isinstance(data["arguments"], dict):
                    raise ValueError("工具参数必须是对象")
                result = GUARD.run(user, data["scenario"], data["query"], data.get("tool"), data.get("arguments"))
            elif self.path == "/api/upload":
                if not all(isinstance(data.get(k), str) and data[k].strip() for k in ("scenario", "title", "text")):
                    raise ValueError("文档字段不能为空")
                result = GUARD.upload(user, data["scenario"], data["title"], data["text"])
            elif self.path == "/api/approve":
                result = GUARD.approve(user, data.get("document_id"))
            else:
                return self.respond(404, {"error": "不存在"})
            self.respond(200, result)
        except PermissionError as exc:
            self.respond(403, {"error": str(exc)})
        except (ValueError, TypeError) as exc:
            self.respond(400, {"error": str(exc)})
        except Exception:
            self.respond(500, {"error": "处理失败"})


if __name__ == "__main__":
    print("演示地址：http://127.0.0.1:8080 （模拟模型，仅本机）", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
