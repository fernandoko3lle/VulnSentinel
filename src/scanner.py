import asyncio
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from utils.http_client import HTTPClient
from utils.payloads import (
    SQLI_PAYLOADS,
    XSS_PAYLOADS,
    CMDI_PAYLOADS,
    TRAVERSAL_PAYLOADS,
)

from utils.logger import log_scan


@dataclass
class Finding:
    target_url: str
    endpoint: str
    param: str
    vuln_type: str
    severity: str
    evidence: str
    recommendation: str
    methodology: str  # obrigatório pra você :)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BasePlugin:
    name: str = "base"

    async def run(self, client: HTTPClient, url: str) -> List[Finding]:
        raise NotImplementedError


class SQLInjectionPlugin(BasePlugin):
    name = "sqli"

    DB_ERROR_SIGNATURES = [
        "sql syntax",
        "mysql",
        "psql:",
        "postgresql",
        "sqlite error",
        "odbc",
        "unclosed quotation mark after the character string",
        "you have an error in your sql",
    ]

    async def run(self, client: HTTPClient, url: str) -> List[Finding]:
        findings: List[Finding] = []

        params = await client.discover_get_params(url)
        if not params:
            return findings

        # baseline: resposta "normal" sem payload malicioso
        baseline_resp = await client.get(url, params=None)
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status

        for param in params:
            param_found = False  # se achar 1 vez pra esse param, pode seguir pro próximo

            for payload in SQLI_PAYLOADS:
                resp = await client.get(url, params={param: payload})
                text_lower = resp.text.lower()

                # 1) Erros explícitos de banco de dados
                if any(err in text_lower for err in self.DB_ERROR_SIGNATURES):
                    findings.append(
                        Finding(
                            target_url=url,
                            endpoint=url,
                            param=param,
                            vuln_type="SQL Injection (erro de banco detectado)",
                            severity="ALTA",
                            evidence=f"Mensagem de erro de banco encontrada na resposta com payload: {payload}",
                            recommendation=(
                                "Use consultas parametrizadas (prepared statements), "
                                "evite concatenação de strings em SQL, e trate mensagens de erro "
                                "para não expor detalhes da camada de banco."
                            ),
                            methodology=(
                                "Metodologia: Identificação de parâmetros na URL com DevTools e inspeção "
                                "da query string; envio de payloads típicos de SQL Injection em cada "
                                "parâmetro e comparação das respostas HTTP, buscando mensagens específicas "
                                "de erro de banco de dados e alterações anômalas no comportamento da página."
                            ),
                        )
                    )
                    param_found = True
                    break

                # 2) Mudança brusca de status code (ex.: 200 -> 500)
                if baseline_status != resp.status and resp.status >= 500:
                    findings.append(
                        Finding(
                            target_url=url,
                            endpoint=url,
                            param=param,
                            vuln_type="SQL Injection (possível impacto em backend)",
                            severity="ALTA",
                            evidence=(
                                f"Status HTTP mudou de {baseline_status} (baseline) para {resp.status} "
                                f"ao enviar payload SQL: {payload}"
                            ),
                            recommendation=(
                                "Valide e sanitize parâmetros antes de construir queries, "
                                "use prepared statements e trate erros de forma genérica para o usuário."
                            ),
                            methodology=(
                                "Metodologia: Coleta de resposta baseline sem payloads maliciosos e, em "
                                "seguida, envio de payloads de SQL Injection variando o parâmetro alvo. "
                                "As respostas são comparadas por código HTTP e padrões de falha no backend "
                                "(ex.: erros 500), indicando possível quebra de lógica SQL."
                            ),
                        )
                    )
                    param_found = True
                    break

                # 3) Diferença grande no tamanho da resposta (boolean-based bem grosseiro)
                length_diff = abs(len(resp.text) - baseline_len)
                if length_diff > 300:
                    findings.append(
                        Finding(
                            target_url=url,
                            endpoint=url,
                            param=param,
                            vuln_type="SQL Injection (comportamento anômalo – heurístico)",
                            severity="MÉDIA",
                            evidence=(
                                f"O tamanho da resposta mudou significativamente após o payload "
                                f"({baseline_len} → {len(resp.text)} caracteres) com: {payload}"
                            ),
                            recommendation=(
                                "Investigar lógica de construção de queries e tratamento de erros. "
                                "Implementar validação de entrada, limitar mensagens de erro e "
                                "utilizar ORMs ou consultas parametrizadas."
                            ),
                            methodology=(
                                "Metodologia: Captura da resposta baseline e posterior envio de payloads "
                                "de SQL Injection no parâmetro analisado, comparando tamanho e estrutura "
                                "da resposta HTML. Grandes diferenças sem alteração legítima esperada "
                                "podem indicar consultas SQL afetadas por entrada não tratada."
                            ),
                        )
                    )
                    # heurística: só marca uma vez por parâmetro pra não poluir demais
                    param_found = True
                    break

            if param_found:
                continue

        return findings


class XSSPlugin(BasePlugin):
    name = "xss"

    async def run(self, client: HTTPClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        params = await client.discover_get_params(url)

        marker = "xh4ck3r123"
        for param in params:
            for payload in XSS_PAYLOADS(marker):
                resp = await client.get(url, params={param: payload})
                content_type = resp.headers.get("Content-Type", "").lower()
                if "text/html" in content_type and marker in resp.text:
                    findings.append(
                        Finding(
                            target_url=url,
                            endpoint=url,
                            param=param,
                            vuln_type="XSS Refletido",
                            severity="ALTA",
                            evidence=f"Payload refletido na resposta com marcador: {marker}",
                            recommendation=(
                                "Escape adequado de saída (HTML/JS), uso de CSP (Content Security Policy), "
                                "validação de entrada e encoding correto nos templates."
                            ),
                            methodology=(
                                "Metodologia: Análise da página alvo com DevTools para identificar "
                                "parâmetros refletidos na resposta, envio de payloads XSS com marcador único "
                                "em cada parâmetro e inspeção do corpo da resposta HTML em busca do marcador "
                                "sem sanitização adequada."
                            ),
                        )
                    )
                    break

        return findings


class CommandInjectionPlugin(BasePlugin):
    name = "cmdi"

    async def run(self, client: HTTPClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        params = await client.discover_get_params(url)

        for param in params:
            for payload in CMDI_PAYLOADS:
                resp = await client.get(url, params={param: payload})
                # heurística bem simples: saída de comandos comuns
                if any(sig in resp.text for sig in ["uid=", "root:x:", "bin/bash"]):
                    findings.append(
                        Finding(
                            target_url=url,
                            endpoint=url,
                            param=param,
                            vuln_type="Command Injection",
                            severity="CRÍTICA",
                            evidence=f"Resposta contém padrões típicos de saída de comandos do sistema.",
                            recommendation=(
                                "Nunca concatenar entrada do usuário em comandos de sistema. "
                                "Use APIs de alto nível, whitelists de parâmetros e sandboxing."
                            ),
                            methodology=(
                                "Metodologia: Identificação de elementos da aplicação que executam "
                                "ação no sistema (ex.: ping, traceroute), envio de payloads que encadeiam "
                                "comandos adicionais e inspeção da resposta para identificar saída de "
                                "comandos locais (ex.: /etc/passwd, uid, etc.)."
                            ),
                        )
                    )
                    break

        return findings


class TraversalPlugin(BasePlugin):
    name = "traversal"

    async def run(self, client: HTTPClient, url: str) -> List[Finding]:
        findings: List[Finding] = []
        params = await client.discover_get_params(url)

        for param in params:
            for payload in TRAVERSAL_PAYLOADS:
                resp = await client.get(url, params={param: payload})
                if "root:x:" in resp.text or "[extensions]" in resp.text.lower():
                    findings.append(
                        Finding(
                            target_url=url,
                            endpoint=url,
                            param=param,
                            vuln_type="Directory Traversal / File Inclusion",
                            severity="ALTA",
                            evidence="Conteúdo de arquivos sensíveis retornados (ex.: /etc/passwd).",
                            recommendation=(
                                "Normalizar e validar caminhos, restringir acessos a diretórios "
                                "específicos, e desativar inclusão dinâmica de arquivos com base "
                                "em parâmetros de usuário."
                            ),
                            methodology=(
                                "Metodologia: Mapeamento de parâmetros que aparentam referenciar "
                                "arquivos/caminhos, envio de payloads com sequências '../' e nomes "
                                "de arquivos sensíveis e análise da resposta HTTP buscando conteúdo "
                                "de arquivos do sistema ou scripts internos."
                            ),
                        )
                    )
                    break

        return findings

class SensitiveInfoPlugin(BasePlugin):
    name = "sensitive_info"

    BODY_PATTERNS = [
        "index of /",
        "directory listing for",
        "traceback (most recent call last)",
        "stack trace",
        "fatal error",
        "warning: ",
        "notice: ",
        "exception:",
    ]

    async def run(self, client: HTTPClient, url: str) -> List[Finding]:
        findings: List[Finding] = []

        resp = await client.get(url, params=None)
        text_lower = resp.text.lower()

        # 1) Directory listing e stack traces na resposta
        for pattern in self.BODY_PATTERNS:
            if pattern in text_lower:
                findings.append(
                    Finding(
                        target_url=url,
                        endpoint=url,
                        param="-",
                        vuln_type="Exposure de informações sensíveis (corpo da resposta)",
                        severity="MÉDIA",
                        evidence=f"Padrão sensível detectado na resposta: '{pattern}'.",
                        recommendation=(
                            "Desabilitar listing de diretórios, ocultar mensagens de erro detalhadas "
                            "em produção e configurar a aplicação para registrar exceções apenas em logs "
                            "internos, retornando mensagens genéricas ao usuário final."
                        ),
                        methodology=(
                            "Metodologia: Acesso ao alvo via HTTP/HTTPS e inspeção detalhada do corpo "
                            "da resposta com auxílio do DevTools e do próprio scanner, buscando padrões "
                            "associados a listagem de diretórios, mensagens de erro detalhadas e stack traces."
                        ),
                    )
                )
                break

        # 2) Headers que revelam demais (Server, X-Powered-By)
        server_header = resp.headers.get("Server")
        x_powered_by = resp.headers.get("X-Powered-By")

        if server_header or x_powered_by:
            header_info = []
            if server_header:
                header_info.append(f"Server: {server_header}")
            if x_powered_by:
                header_info.append(f"X-Powered-By: {x_powered_by}")

            findings.append(
                Finding(
                    target_url=url,
                    endpoint=url,
                    param="-",
                    vuln_type="Exposure de informações sensíveis (headers)",
                    severity="BAIXA",
                    evidence="; ".join(header_info),
                    recommendation=(
                        "Rever configuração do servidor web para minimizar exposição de banners "
                        "de versão (Server, X-Powered-By) e outras informações que facilitem "
                        "fingerprinting da tecnologia utilizada."
                    ),
                    methodology=(
                        "Metodologia: Inspeção dos cabeçalhos HTTP de resposta com DevTools e "
                        "por meio do scanner automatizado, identificando headers que exponham "
                        "nome e versão de servidores, frameworks ou linguagens de backend."
                    ),
                )
            )

        return findings



class Scanner:
    def __init__(self):
        self.plugins: List[BasePlugin] = [
            SQLInjectionPlugin(),
            XSSPlugin(),
            CommandInjectionPlugin(),
            TraversalPlugin(),
            SensitiveInfoPlugin(),  # novo plugin
        ]

    async def scan(self, base_url: str) -> List[Finding]:
        async with HTTPClient(base_url) as client:
            tasks = [plugin.run(client, base_url) for plugin in self.plugins]
            results = await asyncio.gather(*tasks)
        findings: List[Finding] = []
        for plugin_findings in results:
            findings.extend(plugin_findings)
        return findings


async def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TechHacker Web Scanner")
    parser.add_argument("url", help="URL alvo para varredura")
    parser.add_argument("--json", action="store_true", help="Saída em JSON")
    args = parser.parse_args()

    scanner = Scanner()
    findings = await scanner.scan(args.url)

    # logging
    findings_dicts = [f.to_dict() for f in findings]
    if not args.json:
        from report_generator import ReportGenerator
        report = ReportGenerator(findings)
        print(report.to_markdown())
    else:
        print(json.dumps(findings_dicts, indent=2, ensure_ascii=False))

    # sempre registra o scan no histórico
    from report_generator import ReportGenerator
    report = ReportGenerator(findings)
    log_scan(args.url, report.overall_risk_score(), findings_dicts)



if __name__ == "__main__":
    import asyncio
    asyncio.run(main())