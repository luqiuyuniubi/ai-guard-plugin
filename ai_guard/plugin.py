"""Synchronous embedding SDK. All contexts and policy objects are server-owned."""
from dataclasses import dataclass, field
from typing import Callable, Mapping
import uuid
from .types import Identity, Document, DefaultAuthorizer
from .detectors import INJECTION, redact


class SecurityViolation(PermissionError):
    pass


@dataclass(frozen=True)
class RequestContext:
    identity: Identity
    scenario: str
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True)
class Policy:
    allowed_tools: tuple[str, ...] = ()
    max_input_chars: int = 12000


@dataclass(frozen=True)
class Tool:
    # Permission callback MUST validate arguments and actual target ownership.
    authorize: Callable[[RequestContext, dict], bool]
    execute: Callable[[RequestContext, dict], str]


class SecurityPlugin:
    def __init__(self, policies: Mapping[str, Policy], *, authorizer=None,
                 tools: Mapping[str, Tool] | None = None,
                 detector: Callable[[str], bool] | None = None,
                 sanitizer: Callable[[str], str] = redact,
                 audit: Callable[[dict], None] | None = None):
        self.policies = dict(policies)
        self.authorizer = authorizer or DefaultAuthorizer()
        self.tools = dict(tools or {})
        self.detector = detector or (lambda text: bool(INJECTION.search(text)))
        self.sanitizer = sanitizer
        self.audit = audit or (lambda event: None)

    def _policy(self, ctx):
        if not ctx.identity.user_id or not ctx.identity.tenant or ctx.scenario not in self.policies:
            raise SecurityViolation("Unknown identity or scenario")
        return self.policies[ctx.scenario]

    def _event(self, ctx, stage, decision):
        # No raw content, tool arguments, or resource identifiers in default events.
        self.audit({"trace_id": ctx.trace_id, "stage": stage, "decision": decision})

    def before_input(self, ctx: RequestContext, text: str) -> str:
        policy = self._policy(ctx)
        try:
            safe = isinstance(text, str) and len(text) <= policy.max_input_chars and not self.detector(text)
        except Exception as exc:
            raise SecurityViolation("Input inspection unavailable") from exc
        self._event(ctx, "input", "allow" if safe else "deny")
        if not safe:
            raise SecurityViolation("Unsafe input")
        # Redact before external model transmission as well as after generation.
        return self.sanitizer(text)

    def before_context(self, ctx: RequestContext, documents: list[Document]) -> list[Document]:
        self._policy(ctx)
        safe = []
        try:
            for d in documents:
                # Mandatory tenant/status checks cannot be overridden by an adapter.
                allowed = (d.tenant == ctx.identity.tenant and d.scenario == ctx.scenario
                           and d.status == "approved" and self.authorizer.allowed(ctx.identity, d))
                if allowed and not self.detector(d.text):
                    from dataclasses import replace
                    safe.append(replace(d, text=self.sanitizer(d.text), title=self.sanitizer(d.title)))
        except Exception as exc:
            raise SecurityViolation("Context inspection unavailable") from exc
        self._event(ctx, "context", "filtered" if len(safe) != len(documents) else "allow")
        return safe

    def after_output(self, ctx: RequestContext, text: str) -> str:
        self._policy(ctx)
        if not isinstance(text, str):
            raise SecurityViolation("Unsupported output type")
        result = self.sanitizer(text)
        self._event(ctx, "output", "sanitized")
        return result

    def call_tool(self, ctx: RequestContext, name: str, arguments: dict) -> str:
        policy = self._policy(ctx)
        tool = self.tools.get(name)
        if name not in policy.allowed_tools or tool is None or not isinstance(arguments, dict):
            self._event(ctx, "tool", "deny")
            raise SecurityViolation("Tool not allowed")
        import copy
        checked = copy.deepcopy(arguments)
        try:
            allowed = tool.authorize(ctx, copy.deepcopy(checked)) is True
        except Exception as exc:
            raise SecurityViolation("Tool authorization unavailable") from exc
        self._event(ctx, "tool", "allow" if allowed else "deny")
        if not allowed:
            raise SecurityViolation("Tool resource access denied")
        # Executor must enforce authorization atomically with any privileged write.
        return self.after_output(ctx, tool.execute(ctx, checked))

    def protect(self, ctx: RequestContext, query: str, *, retrieve, generate) -> str:
        """Wrap a text RAG operation without owning the model or storage."""
        clean_query = self.before_input(ctx, query)
        documents = self.before_context(ctx, retrieve(ctx, clean_query))
        return self.after_output(ctx, generate(ctx, clean_query, documents))
