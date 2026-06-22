FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask pycryptodome requests

# Copy source
COPY . /app/

# Create data directories
RUN mkdir -p /app/var/keys /app/var/sessions /app/var/tickets /app/var/logs

EXPOSE 5000

CMD ["python", "iremo_clone_server.py"]
