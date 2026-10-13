import hashlib
import json
import re
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from .types import Identity, Document, Authorizer, DefaultAuthorizer
from .detectors import INJECTION, SECRET, PHONE, redact


class ModelAdapter(Protocol):
    def generate(self, query: str, documents: list[Document]) -> str: ...


class DemoModel:
    """Deterministic extractive simulator; does not measure real LLM robustness."""
    def generate(self, query, documents):
        if not documents:
            return "没有可访问且匹配的已审核资料，无法回答。"
        return "\n\n".join(f"{d.title}：{d.text}" for d in documents)


def seed_documents():
    return [
        Document("public-a", "a", "knowledge", "报销制度", "报销上限 500 元，需提交票据。"),
        Document("finance-a", "a", "knowledge", "财务机密", "财务预算 100 万；DEMO_SECRET_FINANCE", ("finance",)),
        Document("public-b", "b", "knowledge", "B 公司制度", "B 公司报销上限 900 元。"),
        Document("order-alice", "a", "support", "Alice 订单", "订单 A001 已发货，联系电话 13800138000。", owner="alice"),
        Document("order-bob", "a", "support", "Bob 订单", "订单 B002 处理中。", owner="bob"),
        Document("sales-a", "a", "analysis", "销售汇总", "销售汇总：一月 100，二月 120，合计 220。", ("analyst",)),
    ]


class Guard:
    def __init__(self, policy_path=None, authorizer=None, model=None, audit_path=None):
        path = policy_path or Path(__file__).resolve().parent.parent / "policies.json"
        self.policies = json.loads(Path(path).read_text(encoding="utf-8"))
        self.authorizer = authorizer or DefaultAuthorizer()
        self.model = model or DemoModel()
        self.documents = seed_documents()
        self.audit_path = Path(audit_path) if audit_path else None
        self.lock = threading.RLock()

    def audit(self, event):
        record = {"time": datetime.now(timezone.utc).isoformat(), **event}
        if self.audit_path:
            with self.lock:
                self.audit_path.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def upload(self, user, scenario, title, text):
        if "admin" not in user.roles:
            raise PermissionError("只有管理员可上传文档")
        if scenario not in self.policies:
            raise ValueError("未知场景")
        d = Document(str(uuid.uuid4()), user.tenant, scenario, title, text, status="pending")
        with self.lock:
            self.documents.append(d)
        self.audit({"event": "upload", "user": user.user_id, "document": d.id,
                    "sha256": hashlib.sha256(text.encode()).hexdigest()})
        return asdict(d)

    def approve(self, user, document_id):
        with self.lock:
            for i, d in enumerate(self.documents):
                if d.id == document_id:
                    if "admin" not in user.roles or d.tenant != user.tenant:
                        raise PermissionError("无审核权限")
                    if INJECTION.search(d.text):
                        raise ValueError("发现可疑指令，文档保持隔离")
                    self.documents[i] = Document(**{**asdict(d), "status": "approved"})
                    self.audit({"event": "approve", "user": user.user_id, "document": d.id})
                    return {"id": d.id, "status": "approved"}
        raise ValueError("文档不存在")

    def run(self, user, scenario, query, tool=None, arguments=None):
        trace_id = str(uuid.uuid4())
        if scenario not in self.policies:
            raise ValueError("未知场景")
        policy = self.policies[scenario]
        result = {"trace_id": trace_id, "scenario": scenario, "mode": "demo",
                  "blocked": False, "citations": [], "steps": []}
        def finish(answer, blocked=False):
            result.update(answer=redact(answer), blocked=blocked)
            self.audit({"event": "request", "trace_id": trace_id, "user": user.user_id,
                        "tenant": user.tenant, "scenario": scenario, "blocked": blocked,
                        "steps": result["steps"], "document_ids": [c["id"] for c in result["citations"]]})
            return result
        if INJECTION.search(query):
            result["steps"].append("输入发现可疑指令")
            return finish("请求包含可疑指令，已拒绝。", True)
        if tool:
            if tool not in policy["tools"]:
                return finish("当前场景不允许该工具。", True)
            if tool == "read_document":
                document_id = (arguments or {}).get("document_id")
                with self.lock:
                    d = next((d for d in self.documents if d.id == document_id), None)
                if not d or d.scenario != scenario or not self.authorizer.allowed(user, d):
                    return finish("工具访问被权限控制拒绝。", True)
                candidates = [d]
            elif tool == "sales_summary":
                with self.lock:
                    candidates = [d for d in self.documents if d.scenario == scenario
                                  and self.authorizer.allowed(user, d)]
                if "analyst" not in user.roles:
                    return finish("仅分析员可执行销售汇总。", True)
            else:
                return finish("未注册的工具。", True)
            result["steps"].append("工具和资源权限校验通过")
        else:
            with self.lock:
                accessible = [d for d in self.documents if d.scenario == scenario
                              and self.authorizer.allowed(user, d)]
            # Minimal lexical retriever; replace with a filtered vector connector.
            terms = re.findall(r"[a-zA-Z0-9]+|[\u4e00-\u9fff]{2}", query.lower())
            def score(d):
                return sum(t in (d.title + d.text).lower() for t in terms)
            candidates = sorted((d for d in accessible if score(d)), key=score, reverse=True)[:3]
            result["steps"].append("已按公司、角色、归属和审核状态过滤检索")
        # Recheck at the context boundary; neither query nor model sets identity.
        safe = []
        for d in candidates:
            if not self.authorizer.allowed(user, d):
                continue
            if INJECTION.search(d.text):
                result["steps"].append("可疑文档已从上下文隔离")
                continue
            safe.append(d)
        result["citations"] = [{"id": d.id, "title": redact(d.title), "version": d.version} for d in safe]
        result["steps"].append("上下文权限复核和内容检查完成")
        answer = self.model.generate(query, safe)
        result["steps"].append("输出敏感标记和手机号脱敏完成")
        return finish(answer)
