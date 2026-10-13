"""Run: python -m examples.embedded"""
from ai_guard import SecurityPlugin, RequestContext, Policy, Identity, Document, Tool, SecurityViolation

# The host business owns its verified identity, data store and model.
orders = {"A001": {"owner": "alice", "tenant": "a", "text": "订单已发货，电话 13800138000"}}

def can_read(ctx, args):
    order = orders.get(args.get("order_id"))
    return bool(order and order["tenant"] == ctx.identity.tenant
                and order["owner"] == ctx.identity.user_id)

plugin = SecurityPlugin(
    {"orders": Policy(allowed_tools=("read_order",)), "handbook": Policy()},
    tools={"read_order": Tool(can_read, lambda ctx, args: orders[args["order_id"]]["text"])})
ctx = RequestContext(Identity("alice", "a", ("customer",)), "orders")
print(plugin.call_tool(ctx, "read_order", {"order_id": "A001"}))

handbook = RequestContext(ctx.identity, "handbook")
def retrieve(ctx, query):
    return [Document("h1", "a", "handbook", "制度", "报销上限 500 元。"),
            Document("h2", "b", "handbook", "其他公司机密", "不能进入模型")]

def generate(ctx, query, documents):
    # Replace with the host application's model call.
    return "\n".join(d.text for d in documents)

print(plugin.protect(handbook, "报销上限是多少", retrieve=retrieve, generate=generate))
try:
    plugin.call_tool(RequestContext(Identity("bob", "a", ()), "orders"),
                     "read_order", {"order_id": "A001"})
except SecurityViolation as exc:
    print("越权访问已拒绝：", exc)
