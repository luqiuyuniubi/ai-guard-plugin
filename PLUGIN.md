# 将 AI Guard 嵌入业务

插件不依赖演示服务、知识库数据或模型供应商，提供同步 Python SDK。安装项目：

```powershell
python -m pip install .
python -m examples.embedded
```

也可以在本项目中直接 import，无需安装。

## 最小接入

```python
from ai_guard import SecurityPlugin, RequestContext, Policy, Identity

guard = SecurityPlugin({"my_business": Policy()})
# 由业务服务端从经过验证的登录状态创建；禁止接受请求体自报身份。
ctx = RequestContext(Identity("alice", "company_a", ("employee",)), "my_business")

answer = guard.protect(
    ctx,
    query,
    retrieve=my_retriever,  # (ctx, clean_query) -> list[Document]
    generate=my_model,     # (ctx, clean_query, safe_documents) -> str
)
```

业务负责将文档转换为 Document，并提供可信的租户、场景、审核状态和权限元数据。缺失的权限信息不能默认当作公开资源。默认授权器中空 roles 表示同公司公开；接入前必须明确这种语义。

## 四个接入点

| 方法 | 嵌入位置 | 行为 |
| --- | --- | --- |
| before_input | 模型/检索调用前 | 输入检查、长度限制、基础脱敏 |
| before_context | 检索/工具返回内容进入模型前 | 公司与场景隔离、审核状态、业务权限检查、注入检查和脱敏 |
| call_tool | 模型提出工具调用之后 | 白名单、参数与资源授权，再执行并脱敏工具结果 |
| after_output | 完整回答返回用户前 | 输出脱敏与审计事件 |

protect 是输入、上下文、输出三个步骤的便利封装，不自动执行模型提出的工具。Agent 的每次工具调用均须经过 call_tool；历史对话、工具返回的文档也必须在进入模型前重新检查。未经检查的数据不得通过旁路拼接到模型上下文。

## 扩展接口

- policies：服务端维护场景到 Policy 的映射；新场景无需修改安全核心。
- authorizer：提供 allowed(identity, document)，对接企业权限服务。异常拒绝整个上下文处理；租户、场景和审核状态检查仍由插件执行。
- detector：text -> bool，可以替换为分类器或组合检测器。返回 True 表示可疑。
- sanitizer：text -> str，可以替换为企业敏感信息检测服务。必须线程安全，并在故障时抛出异常，业务不得回退为未处理数据。
- audit：接收 trace_id/stage/decision，不默认接收正文、用户信息或工具参数。
- tools：名称到 Tool 的映射，每个工具分别提供 authorize(ctx, args) 和 execute(ctx, args)。执行器须校验真实资源、参数类型、租户和归属；有副作用的操作要在执行时原子校验，防止检查后权限变化。

## 支持范围与限制

目前适合 Python 同步、文本类型的 RAG/客服/Agent 接入。不是任意语言的自动注入插件：其他语言需单独部署服务适配器，异步、流式、多模态尚未实现。流式输出不能先发 token 再检查；本版需缓冲完整输出。

插件控制接入路径，无法阻止宿主代码绕过检查，也无法验证外部数据元信息的真实性。入库审核在演示业务中实现，插件检查 approved 状态；真实性、版本和来源审核由业务或后续入库适配器承担。基础正则不能保证识别所有提示词攻击、秘密或污染事实。

SDK 安装包只提供 Python 模块；演示页面与场景文件在源码目录运行。生产场景需补充真实权限接入、模型评估、限流和生命周期管理。
