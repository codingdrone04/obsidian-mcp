FROM python:3.12-alpine

# Build deps (for compiled packages)
RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# User with same UID as host fr0gman33 (1000) for vault write access
RUN addgroup -g 1000 mcp && adduser -u 1000 -G mcp -D mcp
RUN mkdir -p /vault && chown mcp:mcp /vault
RUN mkdir -p /data && chown mcp:mcp /data
USER mcp

VOLUME ["/vault"]
EXPOSE 8000

CMD ["python", "server.py"]
