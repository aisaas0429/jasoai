# utils/idv.py
import re
from datetime import datetime, timedelta

def normalize_phone(raw: str | None) -> str | None:
    if not raw:
        return None
    # 숫자만 추출
    digits = re.sub(r"\D", "", raw)
    # 국제표기 보정 (예: 8210 -> 010)
    if digits.startswith("82") and len(digits) >= 11:
        digits = "0" + digits[2:]
    return digits

def mask_phone(digits: str | None) -> str | None:
    if not digits:
        return None
    d = re.sub(r"\D", "", digits)
    if len(d) == 11:      # 010-****-1234
        return f"{d[:3]}-****-{d[-4:]}"
    if len(d) == 10:      # 011/016 등
        return f"{d[:3]}-***-{d[-4:]}"
    return d

def idv_session_is_fresh(session, max_minutes: int = 15) -> bool:
    ts = session.get("idv_at")
    if not ts:
        return False
    try:
        at = datetime.fromisoformat(ts)
    except Exception:
        return False
    return datetime.utcnow() - at <= timedelta(minutes=max_minutes)