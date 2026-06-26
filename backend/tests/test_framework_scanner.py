from app.scanners.framework_scanner import run


def by_category(findings, category):
    return [f for f in findings if f.category == category]


def test_langchain_bind_tools_with_risky_tool_is_flagged():
    files = {
        "agent.py": "llm_with_tools = llm.bind_tools([send_email, issue_refund])\n"
    }
    findings = run(files)
    tool_findings = by_category(findings, "Tool Permission Risk")
    assert len(tool_findings) == 1
    assert tool_findings[0].severity in {"High", "Medium"}


def test_openai_tool_schema_with_risky_function_is_flagged():
    files = {
        "agent.ts": "const tools = [{ type: 'function', function: { name: 'deleteUser' } }];\n"
    }
    findings = run(files)
    assert len(by_category(findings, "Tool Permission Risk")) == 1


def test_approval_nearby_suppresses_framework_tool_finding():
    files = {
        "agent.py": "approval_required = True\nllm_with_tools = llm.bind_tools([issue_refund])\n"
    }
    findings = run(files)
    assert len(by_category(findings, "Tool Permission Risk")) == 0
