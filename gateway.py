# gateway.py
# -*- coding: utf-8 -*-
import json
import asyncio
import anyio
from typing import Dict, Any, Tuple, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse

# 업스트림(원본) LLM 엔드포인트
OPENAI_ORIGIN = "https://api.openai.com"
GEMINI_ORIGIN = "https://generativelanguage.googleapis.com"

app = FastAPI(title="Cursor LLM Interceptor (vendor-prefix edition)")

# ============ 콘솔 로깅 미들웨어 ============
@app.middleware("http")
async def log_req(request: Request, call_next):
    print(f">> {request.method} {request.url.path}")
    resp = await call_next(request)
    try:
        status = resp.status_code
    except Exception:
        status = "unknown"
    print(f"<< {status} {request.url.path}")
    return resp
# ============================================

# ---- 간단 정책/홀드 상태 (POC) ----
HOLD_ENABLED: bool = True  # True면 정책 히트 시 승인 대기
PENDING: Dict[str, Dict[str, Any]] = {}  # flow-id -> {req_data, approved, rewrite}
SEQ: int = 0

def mask_text(s: str) -> str:
    if not isinstance(s, str):
        return s
    # 필요 시 규칙 확장
    return s.replace("sk-", "sk-****")

def sanitize_body(obj: Any) -> Any:
    """OpenAI(/v1/*)와 Gemini(/v1beta/*) 공통으로 프롬프트 텍스트를 가볍게 변조/마스킹."""
    if isinstance(obj, dict):
        # OpenAI /v1/chat/completions
        if "messages" in obj and isinstance(obj["messages"], list):
            for m in obj["messages"]:
                if isinstance(m, dict) and "content" in m:
                    m["content"] = "[SANITIZED] " + mask_text(m["content"])
        # OpenAI /v1/responses
        if "input" in obj:
            if isinstance(obj["input"], str):
                obj["input"] = "[SANITIZED] " + mask_text(obj["input"])
            elif isinstance(obj["input"], list):
                obj["input"] = ["[SANITIZED] " + mask_text(x) for x in obj["input"]]
        # Gemini /v1beta/models:generateContent
        if "contents" in obj and isinstance(obj["contents"], list):
            for c in obj["contents"]:
                parts = c.get("parts", [])
                for p in parts:
                    if isinstance(p, dict) and "text" in p and isinstance(p["text"], str):
                        p["text"] = "[SANITIZED] " + mask_text(p["text"])
    return obj

# ============ 벤더 프리픽스 라우팅 ============
def split_vendor_and_path(path: str) -> Tuple[Optional[str], str]:
    """
    기대 형태:
      /openai/v1/...
      /gemini/v1beta/...
    반환:
      ("openai", "/v1/...") 또는 ("gemini", "/v1beta/..."), 없으면 (None, 원경로)
    """
    if path.startswith("/openai/"):
        return "openai", path[len("/openai"):]
    if path.startswith("/gemini/"):
        return "gemini", path[len("/gemini"):]
    return None, path

def origin_for(vendor: str) -> str:
    return OPENAI_ORIGIN if vendor == "openai" else GEMINI_ORIGIN
# =============================================

# ------------ 관리/승인 UI (catch-all 보다 위에 둬야 함) ------------
@app.get("/admin", response_class=HTMLResponse)
def admin():
    items = []
    for fid, val in PENDING.items():
        snippet = json.dumps(val["req_data"], ensure_ascii=False, indent=2)[:1200]
        items.append(
            f"<li><b>{fid}</b><br/><pre style='white-space:pre-wrap'>{snippet}</pre>"
            f"<form method='post' action='/admin/approve?fid={fid}' style='display:inline'><button>Approve</button></form> "
            f"<form method='post' action='/admin/approve_rewrite?fid={fid}' style='display:inline'><button>Approve+Rewrite(sanitize)</button></form></li>"
        )
    html = f"""
    <h2>Pending Requests ({len(items)})</h2>
    <ul>{''.join(items) if items else '<i>none</i>'}</ul>
    <hr/>
    <form method="post" action="/admin/toggle"><button>HOLD_ENABLED = {HOLD_ENABLED}</button></form>
    <p><a href="/health">/health</a></p>
    <p><b>사용법</b>: OpenAI Base URL → <code>http://127.0.0.1:8081/openai/v1</code>, Gemini Base URL → <code>http://127.0.0.1:8081/gemini</code></p>
    """
    return HTMLResponse(html)

@app.post("/admin/toggle")
def toggle():
    global HOLD_ENABLED
    HOLD_ENABLED = not HOLD_ENABLED
    return HTMLResponse(f"<a href='/admin'>OK</a> (HOLD_ENABLED={HOLD_ENABLED})")

@app.post("/admin/approve")
def approve(fid: str):
    if fid in PENDING:
        PENDING[fid]["approved"] = True
        return HTMLResponse("<a href='/admin'>Approved</a>")
    raise HTTPException(404, "not found")

@app.post("/admin/approve_rewrite")
async def approve_rewrite(fid: str, request: Request):
    if fid not in PENDING:
        raise HTTPException(404, "not found")
    rw = sanitize_body(PENDING[fid]["req_data"])
    PENDING[fid]["rewrite"] = rw
    PENDING[fid]["approved"] = True
    return HTMLResponse("<a href='/admin'>Approved with rewrite</a>")

@app.get("/health")
def health():
    return {"ok": True, "hold_enabled": HOLD_ENABLED, "pending": len(PENDING)}

# ------------ 포워딩 공통 ------------
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",   # 응답에서는 제거 (길이 불일치 방지)
}

async def stream_forward(req: Request) -> StreamingResponse | JSONResponse:
    # 벤더/내부 경로 분해
    src = urlsplit(str(req.url))
    vendor, inner_path = split_vendor_and_path(src.path)
    if vendor is None:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid route", "hint": "use /openai/... or /gemini/..."},
        )

    # 원 요청 바디
    raw = await req.body()
    content_type = (req.headers.get("content-type") or "").lower()
    body_out = raw

    # JSON 본문이면 정책 검사/홀드/변조
    if "application/json" in content_type:
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            data = None

        hit = bool(data)  # POC: 본문이 있으면 히트
        if hit and HOLD_ENABLED:
            global SEQ
            SEQ += 1
            flow_id = f"flow-{SEQ}"
            PENDING[flow_id] = {"req_data": data, "approved": False, "rewrite": None}
            try:
                with anyio.move_on_after(90):
                    while not PENDING[flow_id]["approved"]:
                        await asyncio.sleep(0.25)
                if not PENDING[flow_id]["approved"]:
                    return JSONResponse(status_code=403, content={"error": "blocked by policy(timeout)"})
            finally:
                pass
            rw = PENDING[flow_id].get("rewrite")
            data = rw if rw is not None else sanitize_body(data)
            body_out = json.dumps(data, ensure_ascii=False).encode("utf-8")
            PENDING.pop(flow_id, None)
        elif hit:
            data = sanitize_body(data)
            body_out = json.dumps(data, ensure_ascii=False).encode("utf-8")

    # 대상 URL 구성 (벤더별 원본으로 포워딩)
    origin = origin_for(vendor)
    tgt = urlsplit(origin)
    forward_url = urlunsplit((tgt.scheme, tgt.netloc, inner_path, src.query, ""))

    # 요청 헤더: httpx가 적절히 세팅하도록 일부 제거
    fwd_headers = {
        k: v for k, v in req.headers.items()
        if k.lower() not in {"host", "content-length", "connection"}
    }

    # 비동기 스트리밍 포워딩
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream(
            req.method, forward_url, headers=fwd_headers, content=body_out
        ) as fwd_resp:

            # 응답 헤더 필터링 (길이/전송방식 충돌 방지)
            resp_headers = {
                k: v for k, v in fwd_resp.headers.items()
                if k.lower() not in HOP_BY_HOP
            }

            async def agen():
                try:
                    async for chunk in fwd_resp.aiter_raw():
                        if chunk:
                            yield chunk
                except httpx.StreamClosed:
                    # 업스트림이 조용히 닫은 경우: 스트림 종료
                    return

            return StreamingResponse(
                agen(),
                status_code=fwd_resp.status_code,
                headers=resp_headers
            )

# ------------ catch-all ------------
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def gateway(path: str, request: Request):
    # /admin, /health 등은 위에서 이미 처리됨
    return await stream_forward(request)
