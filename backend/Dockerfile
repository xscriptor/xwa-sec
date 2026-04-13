FROM mcr.microsoft.com/playwright/python:v1.52.0-jammy

ARG NUCLEI_VERSION=3.3.9

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
	nmap \
	git \
	wget \
	unzip \
	ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
	&& ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
	&& chmod +x /opt/sqlmap/sqlmap.py

RUN set -eux; \
	arch="$(dpkg --print-architecture)"; \
	case "$arch" in \
	  amd64) nuclei_arch="amd64" ;; \
	  arm64) nuclei_arch="arm64" ;; \
	  *) echo "Unsupported architecture: $arch"; exit 1 ;; \
	esac; \
	wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip"; \
	unzip -q /tmp/nuclei.zip -d /tmp; \
	mv /tmp/nuclei /usr/local/bin/nuclei; \
	chmod +x /usr/local/bin/nuclei; \
	rm -rf /tmp/nuclei.zip

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

COPY ./app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
