# VulnSentinel -- Ferramenta de Avaliação de Segurança de Aplicações Web

### Relatório Técnico -- Tecnologias Hackers (Insper)

------------------------------------------------------------------------

# 1. Introdução

O **VulnSentinel** é uma ferramenta de avaliação de segurança para
aplicações web, desenvolvida com foco no **OWASP Top 10**, permitindo a
identificação automatizada de vulnerabilidades através de análise
heurística e coleta de evidências.

O objetivo do sistema é oferecer:

-   Varredura automatizada de URLs
-   Detecção de vulnerabilidades comuns
-   Priorização baseada em severidade
-   Visualização interativa via dashboard
-   Relatórios gerados automaticamente
-   Integração com CI/CD e registro histórico

O projeto foi construído em Python, com FastAPI, aiohttp, Chart.js e
GitHub Actions.

------------------------------------------------------------------------

# 2. Arquitetura do Sistema

A arquitetura do VulnSentinel segue o padrão **modular por plugins**,
facilitando extensões futuras.

    /src
     ├── scanner.py               # Engine principal de varredura
     ├── api.py                   # API REST + dashboard
     ├── report_generator.py      # Geração de relatórios
     ├── config.py                # Configurações globais
     ├── utils/
     │    ├── http_client.py      # Cliente HTTP assíncrono
     │    ├── payloads.py         # Payloads de ataque
     │    └── logger.py           # Histórico JSONL
     ├── tests/
     │    ├── test_scanner.py     # Teste smoke do scanner
     │    └── test_utils.py       # Testes de payloads e logger
     └── templates/
          └── index.html          # Dashboard com gráficos

### 🔧 Fluxo de funcionamento

    URL → Scanner → Plugins → Findings → Severidade → Dashboard/API → Log/Relatório

### 🔌 Plugins implementados

-   SQL Injection (melhorado: baseline diff + erro + comportamento)
-   XSS Refletido (com Content-Type check)
-   Command Injection
-   Directory Traversal
-   Exposure de Informações Sensíveis (headers + body)

### 🎨 Dashboard

-   Score de risco
-   Filtros
-   Gráficos
-   Tabela interativa
-   Distribuição por severidade
-   Distribuição por tipo

------------------------------------------------------------------------

# 3. Metodologia de Testes 

A metodologia segue exatamente o que é solicitado na disciplina:

### 🔎 Etapas aplicadas a **todas as vulnerabilidades**:

1.  **Acesso ao alvo:**

    -   Identificação do protocolo (HTTP/HTTPS)\
    -   Verificação de domínio, rota e parâmetros

2.  **Mapeamento inicial com DevTools:**

    -   Inspeção de requisições
    -   Identificação de método (GET/POST)
    -   Análise de query strings
    -   Headers e cookies retornados

3.  **Validação dos pontos de entrada:**

    -   Confirmar parâmetros vulneráveis
    -   Confirmar endpoints que aceitam input do usuário

4.  **Envio de payloads específicos:**
    Cada plugin utiliza payloads distintos, enviados via requisições
    assíncronas.

5.  **Comparação com baseline:**

    -   Códigos HTTP
    -   Alterações no DOM
    -   Erros do servidor
    -   Mudanças significativas no tamanho da resposta

6.  **Coleta de evidências:**

    -   Trechos HTML retornados
    -   Conteúdo refletido
    -   Status HTTP
    -   Comportamento divergente

7.  **Classificação da severidade:**
    Definida seguindo probabilidade + impacto conforme OWASP:
 
```bash
       CRÍTICA > ALTA > MÉDIA > BAIXA
```
------------------------------------------------------------------------

# 4. Vulnerabilidades Detectadas (Exemplos Reais)

Testes foram realizados em ambientes **oficialmente vulneráveis**:

-   `http://testphp.vulnweb.com/`
-   `http://demo.testfire.net/`
-   `https://google-gruyere.appspot.com/xxxxx`

------------------------------------------------------------------------

## 4.1 SQL Injection (Heurística + erro real)

**Endpoint:**

    http://testphp.vulnweb.com/listproducts.php?cat=1

**Evidências coletadas:** - Mensagens de erro de banco
- Diferença significativa entre resposta baseline e resposta com
payload
- Alteração de status HTTP em alguns casos

**Severidade:** **ALTA**

**Recomendação:** - Parametrizar queries
- Sanitizar entrada
- Remover mensagens detalhadas de erro

------------------------------------------------------------------------

## 4.2 XSS Refletido

**Endpoint:**

    http://testphp.vulnweb.com/search.php?test=query

**Evidências:** - Conteúdo refletido
- HTML retornado sem sanitização
- Uso de content-type text/html permitindo execução

**Severidade:** **ALTA**

**Recomendação:** - Escapagem correta
- Uso de Content Security Policy
- Sanitização de saída

------------------------------------------------------------------------

## 4.3 Exposure de Informações Sensíveis

**Endpoint:**

    http://testphp.vulnweb.com/

**Evidências:** - Header `Server` expondo versão
- Possibilidade de fingerprint

**Severidade:** **BAIXA**

**Recomendação:** - Ocultar banners de servidor
- Configurar `ServerTokens Prod`
- Remover `X-Powered-By`

------------------------------------------------------------------------

# 5. Dashboard Interativo

O dashboard exibe:

-   Score de risco
-   Tabela com filtros
-   Gráfico de severidade
-   Gráfico de tipos
-   Lista de vulnerabilidades

![dashboard](img/dashboard.png)

------------------------------------------------------------------------

# 6. Integração Contínua (CI/CD)

Pipeline configurado com **GitHub Actions**, executando:

-   Instalação do Python
-   Instalação de dependências
-   Execução de `pytest`
-   Smoke test do scanner
-   Upload do log de histórico (`scan_history.jsonl`)

Arquivo completo:
`.github/workflows/security_scan.yml`

**Benefícios:**

-   Validação automática
-   Proteção contra regressões
-   Histórico de qualidade

------------------------------------------------------------------------

# 7. Containerização (Docker)

A aplicação pode ser executada via Docker:

``` bash
docker build -t vulnsentinel .
docker run -p 8000:8000 vulnsentinel
```

Permite fácil distribuição e rodar sem instalar dependências locais.

------------------------------------------------------------------------

# 8. Estrutura Final do Projeto

    src
    docs
    .github/workflows
    templates
    tests

Principais arquivos:

-   `scanner.py`
-   `api.py`
-   `config.py`
-   `logger.py`
-   `index.html`
-   `pytest` - tests
-   `workflow CI`
-   `Dockerfile`

------------------------------------------------------------------------

# 9. Conclusão

O VulnSentinel cumpre todos os requisitos da avaliação:

### ✔ Plugins de múltiplas vulnerabilidades

### ✔ Análise heurística com baseline e evidências

### ✔ Dashboard completo e interativo

### ✔ Classificação de severidade + score de risco

### ✔ Relatório automatizado

### ✔ Logs persistentes

### ✔ Testes automatizados

### ✔ CI/CD operacional

### ✔ Arquitetura modular e expansível

O projeto está pronto para apresentação, publicação e futuras melhorias
como:

-   SSRF
-   Broken Authentication
-   CSRF
-   Active Scan com ZAP
-   Modo spider

------------------------------------------------------------------------

# 10. Referências

-   OWASP Top 10
-   aiohttp docs
-   FastAPI docs
-   Chart.js docs
-   VulnWeb / Acunetix
-   TestFire demo
-   Google Gruyere