# Container image for code-dpdp CLI Compliance Scanner
FROM python:3.12-slim

# System dependencies: git, bash
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python packages
COPY python/ /app/python/
COPY src/ /app/src/
COPY bin/ /app/bin/
COPY package.json /app/

# Install python dependencies
RUN pip install --no-cache-dir \
    rich \
    reportlab \
    pyyaml \
    pydantic \
    requests

RUN chmod +x /app/bin/code-dpdp && \
    ln -sf /app/bin/code-dpdp /usr/local/bin/code-dpdp

WORKDIR /workspace

ENTRYPOINT ["code-dpdp"]
CMD ["--help"]
