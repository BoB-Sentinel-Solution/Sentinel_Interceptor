# Sentinel_Proxy
LLM / MCP 사용 환경에 한정한 Sentinel 프록시

LLM/MCP 트래픽만 인터셉트하고, mTLS로 검사 서버(/inspect) 및 로거 서버(/log)와 통신하는 애드온 라이브러리.

## 설치
```bash
pip install -e .
