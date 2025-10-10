import os
import re
import base64
import asyncio
from typing import Optional, Dict, Any, List
from mitmproxy import http, ctx

from ..filters import LLMFilter, DEFAULT_HOST_PATTERNS, DEFAULT_PATH_HINTS
from ..inspector import InspectorClient
from ..logger import LoggerClient

SENSITIVE_HDRS = re.compile(
    r"^(authorization|cookie|x-api-key|proxy-authorization|set-cookie)$", re.I
)

def _redact_headers(h: http.Headers) -> dict:
    out = {}
    for k, v in h.items(multi=True):
        if SENSITIVE_HDRS.match(k):
            out[k] = v[:4] + "****" + v[-4:] if len(v) > 12 else "***"
        else:
            out[k] = v
    return out

class LLMProxyMitm:
    """
    - LLM/MCP만 가로채 동기 검사(allow/mask/block)
    - 검사 서버/로거 서버와 mTLS 통신
    - fail-open(default): 검사 서버 에러 시 통과 / false면 503
    """
    def __init__(
        self,
        inspector: Optional[InspectorClient] = None,
        llm_filter: Optional[LLMFilter] = None,
        logger: Optional[LoggerClient] = None,
        max_body: int = int(os.getenv("MAX_BODY_BYTES", "1048576")),
        fail_open: bool = os.getenv("FAIL_OPEN", "true").lower() == "true",
        concurrency: int = int(os.getenv("INSPECT_CONCURRENCY", "64")),
    ):
        self.inspector = inspector or InspectorClient()
        self.filter = llm_filter or LLMFilter(DEFAULT_HOST_PATTERNS, DEFAULT_PATH_HINTS, True)
        self.logger = logger or LoggerClient()
        self.max_body = max_body
        self.fail_open = fail_open
        self.sem = asyncio.Semaphore(concurrency)

    def load(self, loader):
        ctx.log.info("[sentinel-proxy] addon loaded (LLM/MCP only)")

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        if not self.filter.is_llm_request(req.scheme, req.host, req.path):
            return  # LLM/MCP 이외는 터치하지 않음
        asyncio.get_event_loop().run_until_complete(self._inspect_and_maybe_modify(flow))

    async def _inspect_and_maybe_modify(self, flow: http.HTTPFlow):
        req = flow.request
        raw = req.raw_content or b""
        if len(raw) > self.max_body:
            head, tail = raw[:512], raw[-512:]
            body_b64 = base64.b64encode(head + b"...TRUNCATED..." + tail).decode()
        else:
            body_b64 = base64.b64encode(raw).decode() if raw else None

        payload = {
            "time": None,  # 서버에서 수신시각 기록 권장
            "interface": "llm",
            "direction": "request",
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path.split("?", 1)[0],
            "query": req.query or "",
            "headers": _redact_headers(req.headers),
            "body_b64": body_b64,
            "client_ip": flow.client_conn.address[0] if flow.client_conn.address else None,
            "server_ip": None,
            "tags": self._infer_tags(req.host, req.path),
        }

        try:
            async with self.sem:
                decision: Dict[str, Any] = await self.inspector.inspect(payload)
        except Exception as e:
            ctx.log.warn(f"[sentinel-proxy] inspector error: {e!r} (fail_open={self.fail_open})")
            if self.fail_open:
                return
            flow.response = http.Response.make(
                503, b"Inspector unavailable", {"Content-Type": "text/plain"}
            )
            return

        d = decision.get("decision", "allow")
        masked_b64 = decision.get("masked_body_b64")

        # 로깅은 비동기로 fire-and-forget
        asyncio.create_task(self._log_safe(payload, decision))

        if d == "block":
            flow.response = http.Response.make(
                403, b"Blocked by policy", {"Content-Type": "text/plain"}
            )
        elif d == "mask" and masked_b64:
            try:
                new_body = base64.b64decode(masked_b64)
                flow.request.raw_content = new_body
                if "content-length" in flow.request.headers:
                    flow.request.headers["content-length"] = str(len(new_body))
            except Exception as e:
                ctx.log.warn(f"[sentinel-proxy] mask decode error: {e!r}")
                if not self.fail_open:
                    flow.response = http.Response.make(
                        500, b"Masking error", {"Content-Type": "text/plain"}
                    )

    async def _log_safe(self, request_payload: Dict[str, Any], decision: Dict[str, Any]):
        try:
            if not self.logger or not self.logger.enabled:
                return
            # 로거로 보낼 합본 페이로드(서버가 해시/미리보기로 처리)
            payload = {
                "time": request_payload.get("time"),
                "interface": request_payload.get("interface", "llm"),
                "method": request_payload.get("method"),
                "scheme": request_payload.get("scheme"),
                "host": request_payload.get("host"),
                "port": request_payload.get("port"),
                "path": request_payload.get("path"),
                "query": request_payload.get("query", ""),
                "headers": request_payload.get("headers", {}),
                "body_b64": request_payload.get("body_b64"),
                "client_ip": request_payload.get("client_ip"),
                "tags": request_payload.get("tags", []),
                "decision": decision.get("decision", "allow"),
                "reason": decision.get("reason", "clean"),
                "rules_hit": decision.get("rules_hit", []),
                "masked_body_b64": decision.get("masked_body_b64"),
            }
            await self.logger.send(payload)
        except Exception:
            pass

    def _infer_tags(self, host: str, path: str) -> List[str]:
        tags: List[str] = []
        h = (host or "").lower()
        if "openai" in h: tags.append("openai")
        if "anthropic" in h or "claude" in h: tags.append("anthropic")
        if "googleapis" in h or "gemini" in h: tags.append("gemini")
        if "groq" in h: tags.append("groq")
        if "deepseek" in h: tags.append("deepseek")
        if "/v1/chat/completions" in path or "/messages" in path: tags.append("chat")
        if "/mcp/" in path: tags.append("mcp")
        return tags

def create_addon() -> LLMProxyMitm:
    """
    외부에서 import해서 mitmproxy addons에 주입할 때 사용.
    예)
      from sentinel_proxy.engines.mitm_engine import create_addon
      addons = [create_addon()]
    """
    return LLMProxyMitm()
