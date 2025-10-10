# run_addon.py
from sentinel_proxy.engines.mitm_engine import create_addon
addons = [create_addon()]  # mitmproxy가 이 심볼을 자동 인식
