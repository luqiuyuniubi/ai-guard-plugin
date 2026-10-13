"""Integration contracts, independent of demo data and HTTP server."""
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Identity:
    user_id: str
    tenant: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class Document:
    id: str
    tenant: str
    scenario: str
    title: str
    text: str
    roles: tuple[str, ...] = ()
    owner: str = ""
    status: str = "approved"
    version: int = 1


class Authorizer(Protocol):
    def allowed(self, user: Identity, document: Document) -> bool: ...


class DefaultAuthorizer:
    def allowed(self, user, document):
        return (user.tenant == document.tenant
                and document.status == "approved"
                and (not document.roles or bool(set(user.roles) & set(document.roles)))
                and (not document.owner or document.owner == user.user_id))
