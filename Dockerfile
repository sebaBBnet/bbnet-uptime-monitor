FROM python:3.11-slim

WORKDIR /app

# Install ping utility
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 9000

# Single worker (pinger + alerter run as background threads — must not be forked).
# 8 threads handles concurrent HTTP requests without blocking.
CMD ["gunicorn", "wsgi:app", \
     "--bind", "0.0.0.0:9000", \
     "--workers", "1", \
     "--threads", "8", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
