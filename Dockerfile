# ============================
# VulnSentinel – Dockerfile
# ============================

FROM python:3.10-slim

# Evita criação de arquivos .pyc e força flush imediato no stdout
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Criar diretório da aplicação
WORKDIR /app

# Copiar requirements
COPY src/requirements.txt .

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar projeto inteiro
COPY src/ .

# Expor API
EXPOSE 8000

# Comando para iniciar FastAPI + Uvicorn
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
