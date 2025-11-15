import os
import sys
import asyncio

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner import Scanner  # agora funciona


def test_scanner_runs_on_httpbin():
    """
    Smoke test: garante que o scanner roda em um alvo simples
    sem levantar exceção, e retorna uma lista de findings.
    """
    scanner = Scanner()
    findings = asyncio.run(scanner.scan("https://httpbin.org/get?test=1"))

    assert isinstance(findings, list)
    for f in findings:
        # checa estrutura básica
        assert hasattr(f, "vuln_type")
        assert hasattr(f, "severity")
        assert hasattr(f, "endpoint")
