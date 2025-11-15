# src/utils/logger.py
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

import config


def log_scan(url: str, risk_score: int, findings: List[Dict[str, Any]]) -> None:
    """
    Registra cada scan em um arquivo JSONL (1 linha JSON por scan).
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "risk_score": risk_score,
        "findings_count": len(findings),
        "findings": findings,
    }
    try:
        with open(config.LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        # logger nunca deve quebrar a ferramenta; se falhar, ignora
        pass
