FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY python/ /app/python/
COPY data/ /app/data/
COPY src/ /app/src/
COPY bin/ /app/bin/
COPY package.json /app/

RUN chmod +x /app/bin/code-dpdp && \
    ln -sf /app/bin/code-dpdp /usr/local/bin/code-dpdp

WORKDIR /workspace

ENTRYPOINT ["code-dpdp"]
CMD ["--help"]
