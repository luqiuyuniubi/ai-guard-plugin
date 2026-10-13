"""Embeddable AI security hooks and optional demo application."""
from .types import Identity, Document
from .plugin import SecurityPlugin, RequestContext, Policy, Tool, SecurityViolation

__all__ = ["SecurityPlugin", "RequestContext", "Policy", "Tool",
           "SecurityViolation", "Identity", "Document"]
