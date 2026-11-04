FROM python:3.12-slim

WORKDIR /app
RUN useradd --create-home --uid 10001 mcpuser

COPY pyproject.toml README.md ./
COPY sec360_mcp ./sec360_mcp
RUN pip install --no-cache-dir .

USER mcpuser
EXPOSE 9000

ENV SEC360_MCP_TRANSPORT=streamable-http \
    SEC360_MCP_HOST=0.0.0.0 \
    SEC360_MCP_PORT=9000

CMD ["sec360-mcp"]
