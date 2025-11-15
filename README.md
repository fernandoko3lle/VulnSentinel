# 🔎 VulnSentinel

### Web Security Scanner -- Tecnologias Hackers (Insper)

O **VulnSentinel** é uma ferramenta de avaliação automatizada de
segurança para aplicações web, desenvolvida com foco no **OWASP Top
10**, utilizando análise heurística, dashboard interativo e pipeline
CI/CD para garantir qualidade contínua.

Este repositório contém o código-fonte completo do projeto, incluindo
scanner, dashboard, API, testes e workflow de integração contínua.

------------------------------------------------------------------------

# 📘 Documentação Completa

📄 **Relatório Técnico (Markdown):**\
👉 `docs/Relatorio_Tecnico.md`

------------------------------------------------------------------------

# 🎥 Vídeo Demonstrativo

🔗 *Link para o vídeo de apresentação:*\
➡️  https://youtu.be/HkyQ8l8LyUM

------------------------------------------------------------------------

# 🚀 Como Executar o Projeto

### 1. Clonar o repositório

``` bash
git clone https://github.com/SEU-USUARIO/VulnSentinel.git
cd VulnSentinel/src
```

### 2. Criar ambiente virtual

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependências

``` bash
pip install -r requirements.txt
```

### 4. Rodar a API + Dashboard

``` bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

Acesse:\
👉 **http://localhost:8000/** (Dashboard)\
👉 **http://localhost:8000/docs** (Swagger UI)

------------------------------------------------------------------------

# 🧪 Testes Automatizados

``` bash
pytest
```

------------------------------------------------------------------------

# 👁️ Sobre o Dashboard

-   Score de risco
-   Gráfico de severidade
-   Gráfico por tipo
-   Tabela filtrável
-   Evidências

Interface feita com **FastAPI + Jinja2 + Chart.js**.

------------------------------------------------------------------------

# 🔧 Arquitetura

    /src
     ├── api.py
     ├── scanner.py
     ├── report_generator.py
     ├── config.py
     ├── utils/
     ├── templates/
     └── tests/

------------------------------------------------------------------------

# ⚙️ CI/CD

Workflow CI com GitHub Actions: - Instala dependências\
- Executa testes
- Smoke test
- Upload de artefatos

Arquivo:\
`.github/workflows/security_scan.yml`

------------------------------------------------------------------------


# 🐳 Docker

O VulnSentinel pode ser executado **100% dentro de um container Docker**, sem necessidade de ambiente virtual ou instalação manual de dependências.

A seguir estão as formas recomendadas de execução:

---

## ✔️ Opção 1 — Executar usando Docker local (build + run)

1️⃣ Na **raiz do projeto**, onde está o `Dockerfile`, execute o build:

```bash
docker build -t vulnsentinel .
```

2️⃣ Em seguida, inicie o container:

```bash
docker run -p 8000:8000 vulnsentinel
```
* Acesse:

```bash
👉 http://localhost:8000/ — Dashboard

👉 http://localhost:8000/docs — Swagger UI
```
------------------------------------------------------------------------

# 📬 Contato

Desenvolvido por **Fernando Koelle**
Tecnologias Hackers -- Insper