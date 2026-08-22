"""OAuth-authenticated Codex Responses client with no provider-owned tools."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Protocol

import httpx
from pydantic import ValidationError

from netsage.ai.providers.codex.models import CodexStructuredOutput
from netsage.ai.providers.openai_codex.models import (
    CodexOAuthErrorCode,
    CodexOAuthTokenBundle,
)
from netsage.ai.providers.openai_codex.protocol import (
    CODEX_INFERENCE_BASE_URL,
    CODEX_ORIGINATOR,
    CODEX_RESPONSES_PATH,
)
from netsage.state import OpenAIReasoningEffort

_MAX_RESPONSE_BYTES = 4_000_000
_MAX_OUTPUT_BYTES = 1_000_000


class CodexOAuthInferenceError(RuntimeError):
    def __init__(self, code: CodexOAuthErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class CodexOAuthInferenceClient(Protocol):
    async def complete_structured(
        self,
        tokens: CodexOAuthTokenBundle,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: OpenAIReasoningEffort,
    ) -> CodexStructuredOutput: ...


class OfficialCodexOAuthInferenceClient(CodexOAuthInferenceClient):
    """Use the experimental Codex backend with explicit NetSage identification."""

    def __init__(
        self,
        *,
        base_url: str = CODEX_INFERENCE_BASE_URL,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 300.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._timeout = httpx.Timeout(timeout=timeout, connect=min(timeout, 10.0))

    async def complete_structured(
        self,
        tokens: CodexOAuthTokenBundle,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: OpenAIReasoningEffort,
    ) -> CodexStructuredOutput:
        account_id = tokens.account_id
        if account_id is None:
            raise CodexOAuthInferenceError(
                CodexOAuthErrorCode.AUTHENTICATION_EXPIRED,
                "Codex authentication has no usable account identifier.",
            )
        payload = _build_request_payload(
            input_text=input_text,
            instructions=instructions,
            model=model,
            reasoning_effort=reasoning_effort,
        )
        headers = {
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {tokens.access_token.get_secret_value()}",
            "ChatGPT-Account-ID": account_id,
            "Content-Type": "application/json",
            "User-Agent": "netsage/0.1.0.dev0",
            "originator": CODEX_ORIGINATOR,
        }
        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                async with client.stream(
                    "POST",
                    CODEX_RESPONSES_PATH,
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        raise _status_error(response.status_code)
                    output = await _read_structured_output(response.aiter_lines())
        except CodexOAuthInferenceError:
            raise
        except httpx.TimeoutException as error:
            raise CodexOAuthInferenceError(
                CodexOAuthErrorCode.TIMEOUT,
                "Codex inference timed out.",
            ) from error
        except httpx.HTTPError as error:
            raise CodexOAuthInferenceError(
                CodexOAuthErrorCode.INFERENCE_UNAVAILABLE,
                "Codex OAuth inference is currently unavailable.",
            ) from error
        try:
            return CodexStructuredOutput.model_validate_json(output)
        except ValidationError as error:
            raise CodexOAuthInferenceError(
                CodexOAuthErrorCode.OUTPUT_INVALID,
                "Codex returned no validated structured provider response.",
            ) from error


def _build_request_payload(
    *,
    input_text: str,
    instructions: str,
    model: str,
    reasoning_effort: OpenAIReasoningEffort,
) -> dict[str, object]:
    return {
        "model": model,
        "instructions": instructions,
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": input_text}],
            }
        ],
        "reasoning": {"effort": reasoning_effort},
        "text": {
            "format": {
                "type": "json_schema",
                "name": "netsage_provider_response",
                "strict": True,
                "schema": _strict_json_schema(CodexStructuredOutput.model_json_schema()),
            }
        },
        "store": False,
        "stream": True,
    }


async def _read_structured_output(lines: AsyncIterator[str]) -> str:
    data_lines: list[str] = []
    output_parts: list[str] = []
    total_bytes = 0
    output_bytes = 0
    completed = False
    async for line in lines:
        total_bytes += len(line.encode("utf-8")) + 1
        if total_bytes > _MAX_RESPONSE_BYTES:
            raise CodexOAuthInferenceError(
                CodexOAuthErrorCode.OUTPUT_INVALID,
                "Codex inference response exceeded the safe size limit.",
            )
        if line == "":
            if data_lines:
                event = _parse_sse_event("\n".join(data_lines))
                data_lines.clear()
                event_type = event.get("type")
                if event_type == "response.output_text.delta":
                    delta = event.get("delta")
                    if not isinstance(delta, str):
                        raise _invalid_stream()
                    output_bytes += len(delta.encode("utf-8"))
                    if output_bytes > _MAX_OUTPUT_BYTES:
                        raise _invalid_stream("Codex structured output exceeded the safe limit.")
                    output_parts.append(delta)
                elif event_type == "response.completed":
                    completed = True
                    if not output_parts:
                        extracted = _completed_output_text(event)
                        output_bytes = len(extracted.encode("utf-8"))
                        if output_bytes > _MAX_OUTPUT_BYTES:
                            raise _invalid_stream(
                                "Codex structured output exceeded the safe limit."
                            )
                        output_parts.append(extracted)
                elif event_type in {"error", "response.failed", "response.incomplete"}:
                    raise CodexOAuthInferenceError(
                        CodexOAuthErrorCode.INFERENCE_UNAVAILABLE,
                        "Codex did not complete the inference request.",
                    )
            continue
        if line.startswith("data:"):
            value = line[5:].lstrip()
            if value != "[DONE]":
                data_lines.append(value)
    if data_lines:
        event = _parse_sse_event("\n".join(data_lines))
        if event.get("type") == "response.completed":
            completed = True
            if not output_parts:
                output_parts.append(_completed_output_text(event))
    if not completed or not output_parts:
        raise _invalid_stream()
    return "".join(output_parts)


def _parse_sse_event(value: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise _invalid_stream() from error
    if not isinstance(parsed, dict):
        raise _invalid_stream()
    return parsed


def _completed_output_text(event: dict[str, object]) -> str:
    response = event.get("response")
    if not isinstance(response, dict):
        raise _invalid_stream()
    output = response.get("output")
    if not isinstance(output, list):
        raise _invalid_stream()
    texts: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and part.get("type") == "output_text":
                text = part.get("text")
                if isinstance(text, str):
                    texts.append(text)
    if not texts:
        raise _invalid_stream()
    return "".join(texts)


def _status_error(status_code: int) -> CodexOAuthInferenceError:
    if status_code in {400, 422}:
        return CodexOAuthInferenceError(
            CodexOAuthErrorCode.OUTPUT_INVALID,
            "Codex rejected the structured inference request.",
        )
    if status_code in {401, 403}:
        return CodexOAuthInferenceError(
            CodexOAuthErrorCode.AUTHENTICATION_EXPIRED,
            "Codex authentication expired. Run: netsage ai codex login",
        )
    if status_code == 404:
        return CodexOAuthInferenceError(
            CodexOAuthErrorCode.MODEL_UNAVAILABLE,
            "The configured Codex model is unavailable.",
        )
    if status_code == 429:
        return CodexOAuthInferenceError(
            CodexOAuthErrorCode.RATE_LIMITED,
            "Codex subscription usage is currently rate limited.",
        )
    return CodexOAuthInferenceError(
        CodexOAuthErrorCode.INFERENCE_UNAVAILABLE,
        "Codex OAuth inference is currently unavailable.",
    )


def _invalid_stream(
    message: str = "Codex returned an invalid response stream.",
) -> CodexOAuthInferenceError:
    return CodexOAuthInferenceError(CodexOAuthErrorCode.OUTPUT_INVALID, message)


def _strict_json_schema(schema: dict[str, object]) -> dict[str, object]:
    """Normalize every object for strict Responses structured-output validation."""

    normalized: dict[str, object] = {}
    for key, value in schema.items():
        if isinstance(value, dict):
            normalized[key] = _strict_json_schema(value)
        elif isinstance(value, list):
            normalized[key] = [
                _strict_json_schema(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            normalized[key] = value
    properties = normalized.get("properties")
    if isinstance(properties, dict):
        normalized["additionalProperties"] = False
        normalized["required"] = list(properties)
    return normalized
