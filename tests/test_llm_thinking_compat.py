"""GLM/Qwen 思考模型：回传 reasoning_content、关思考、抬输出上限。"""
from __future__ import annotations

from types import SimpleNamespace

from app.llm.client import (
    assistant_history_message,
    disable_thinking_extra_body,
    prepare_openai_extra_body,
    preserves_assistant_reasoning,
    thinking_max_tokens,
    _coerce_chat_message,
)


def test_glm_and_qwen_need_reasoning_replay():
    assert preserves_assistant_reasoning("glm-5.3")
    assert preserves_assistant_reasoning("GLM-4.5-Air")
    assert preserves_assistant_reasoning("qwen3-max")
    assert preserves_assistant_reasoning("kimi-k3")
    assert not preserves_assistant_reasoning("gpt-4o")
    assert not preserves_assistant_reasoning("deepseek-chat")


def test_disable_thinking_flags_match_provider_dialect():
    assert disable_thinking_extra_body("glm-5.3") == {"thinking": {"type": "disabled"}}
    assert disable_thinking_extra_body("kimi-k3") == {"thinking": {"type": "disabled"}}
    assert disable_thinking_extra_body("qwen3-max") == {"enable_thinking": False}
    assert disable_thinking_extra_body("gpt-4o") == {}
    assert disable_thinking_extra_body(
        "glm-5.3",
        "https://llm-example.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    ) == {}


def test_assistant_history_keeps_reasoning_and_tool_calls():
    msg = SimpleNamespace(
        content="ok",
        reasoning_content="plan the next http_request",
        tool_calls=[SimpleNamespace(
            id="c1",
            type="function",
            function=SimpleNamespace(name="http_request", arguments='{"url":"https://x"}'),
        )],
    )
    out = assistant_history_message(msg)
    assert out["reasoning_content"] == "plan the next http_request"
    assert out["tool_calls"][0]["function"]["name"] == "http_request"


def test_coerce_dict_keeps_reasoning_content():
    out = _coerce_chat_message({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "reasoning_content": "think first",
                "tool_calls": [{
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "http_request", "arguments": "{}"},
                }],
            }
        }]
    })
    assert out.reasoning_content == "think first"
    assert out.tool_calls[0].function.name == "http_request"


def test_prepare_extra_body_disables_thinking_and_passthrough_messages():
    messages = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "reasoning_content": "plan"},
    ]
    extra = prepare_openai_extra_body(
        "glm-5.3",
        messages,
        tools=[{"type": "function"}],
    )
    assert extra["thinking"] == {"type": "disabled"}
    assert extra["messages"] is not messages
    assert extra["messages"][1]["reasoning_content"] == "plan"


def test_prepare_extra_body_skips_thinking_disable_on_aliyun_glm():
    extra = prepare_openai_extra_body(
        "glm-5.3",
        [{"role": "user", "content": "go"}],
        tools=[{"type": "function"}],
        base_url="https://ws-example.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    )
    assert "thinking" not in extra
    assert "enable_thinking" not in extra


def test_thinking_models_raise_max_tokens_when_tools_present():
    assert thinking_max_tokens("glm-5.3", 4096, tools=[{"type": "function"}]) >= 16384
    assert thinking_max_tokens("gpt-4o", 4096, tools=[{"type": "function"}]) == 4096
    assert thinking_max_tokens("glm-5.3", 4096, tools=None) == 4096
