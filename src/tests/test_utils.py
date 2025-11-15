import os
import sys
import json

# Deixa a pasta src no sys.path, igual ao test_scanner
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config
from utils.payloads import XSS_PAYLOADS, SQLI_PAYLOADS, CMDI_PAYLOADS, TRAVERSAL_PAYLOADS
from utils.logger import log_scan


def test_xss_payloads_contain_marker():
    marker = "test-marker-123"
    payloads = XSS_PAYLOADS(marker)

    assert len(payloads) > 0
    for p in payloads:
        assert marker in p, "Marker deve aparecer em todos os payloads de XSS"


def test_basic_payload_lists_not_empty():
    assert len(SQLI_PAYLOADS) > 0
    assert len(CMDI_PAYLOADS) > 0
    assert len(TRAVERSAL_PAYLOADS) > 0


def test_log_scan_writes_jsonl(tmp_path, monkeypatch):
    # usa tmp_path do pytest pra não usar o arquivo real
    fake_log_file = tmp_path / "scan_history_test.jsonl"

    # monkeypatch no config.LOG_FILE_PATH
    monkeypatch.setattr(config, "LOG_FILE_PATH", str(fake_log_file))

    url = "https://example.com"
    risk_score = 42
    findings = [
        {
            "vuln_type": "Teste",
            "severity": "MÉDIA",
            "endpoint": url,
            "param": "q",
            "evidence": "exemplo",
            "recommendation": "nenhuma",
            "methodology": "teste",
            "target_url": url,
        }
    ]

    log_scan(url, risk_score, findings)

    # verifica se o arquivo foi criado
    assert fake_log_file.exists()

    # lê e valida o JSONL
    content = fake_log_file.read_text(encoding="utf-8").strip()
    assert content != ""

    data = json.loads(content)
    assert data["url"] == url
    assert data["risk_score"] == risk_score
    assert data["findings_count"] == len(findings)
    assert isinstance(data["findings"], list)
    assert data["findings"][0]["vuln_type"] == "Teste"
