import re
from typing import Iterable, List

DEFAULT_HOST_PATTERNS = [
    r"^api\.openai\.com$",
    r"^chat\.openai\.com$",
    r"^api\.anthropic\.com$",
    r".*\.claude\.ai$",
    r"^generativelanguage\.googleapis\.com$",
    r".*\.googleapis\.com$",
    r"^gemini\.google\.com$",
    r"^api\.groq\.com$",
    r"^api\.deepseek\.com$",
]
DEFAULT_PATH_HINTS = [
    "/v1/chat/completions",
    "/v1/messages",
    "/v1/responses",
    "/mcp/",
]

class LLMFilter:
    """
    - HTTPS만, LLM/MCP 대상만 골라 인터셉트.
    - host 패턴(정규식) 또는 path 힌트가 매칭되면 LLM 트래픽으로 간주.
    """
    def __init__(
        self,
        host_patterns: Iterable[str] = DEFAULT_HOST_PATTERNS,
        path_hints: Iterable[str] = DEFAULT_PATH_HINTS,
        https_only: bool = True,
    ):
        self.host_res: List[re.Pattern] = [re.compile(p, re.I) for p in host_patterns]
        self.path_hints = list(path_hints)
        self.https_only = https_only

    def match_host(self, host: str) -> bool:
        return any(r.match(host) for r in self.host_res)

    def match_path(self, path: str) -> bool:
        return any(h in path for h in self.path_hints)

    def is_llm_request(self, scheme: str, host: str, path: str) -> bool:
        if self.https_only and scheme.lower() != "https":
            return False
        return self.match_host(host) or self.match_path(path)
