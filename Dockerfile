FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/root/.foundry/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge) — needed by the Gatekeeper's EVM verification step.
RUN curl -L https://foundry.paradigm.xyz | bash && foundryup

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

# Verify toolchain present; contracts are compiled on-demand by the pipeline.
RUN forge --version && python -c "import z3, langchain_core, langgraph; print('deps ok')"

ENTRYPOINT ["python", "main.py"]
