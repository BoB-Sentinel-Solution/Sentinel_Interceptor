import os
import httpx
from typing import Dict, Any

class InspectorClient:
    """
    검사 서버(/inspect)와 mTLS로 통신.
    - request payload(JSON) → decision JSON {"decision":"allow|mask|block", ...}
    """
    def __init__(
        self,
        url: str | None = None,
        ca_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
        timeout_s: float = 3.0,
    ):
        self.url = url or os.getenv("INSPECTOR_URL", "https://localhost:8000/inspect")
        self.verify = ca_file or os.getenv("TLS_CA_FILE", "./certs/ca.pem")
        self.cert = (
            cert_file or os.getenv("TLS_CLIENT_CERT", "./certs/client_cert.pem"),
            key_file or os.getenv("TLS_CLIENT_KEY", "./certs/client_key.pem"),
        )
        self.timeout = httpx.Timeout(timeout_s)

    async def inspect(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(
            verify=self.verify,
            cert=self.cert,
            http2=True,
            timeout=self.timeout,
        ) as cli:
            r = await cli.post(self.url, json=payload)
            r.raise_for_status()
            return r.json()
