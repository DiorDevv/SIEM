FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir requests pyyaml psutil

COPY . .

ENV MANAGER_URL=http://backend:8000

CMD ["python", "agent.py"]
