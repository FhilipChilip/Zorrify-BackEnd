# Imagen del backend (API) de Zorryfy. No incluye el frontend: se publica aparte.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY db ./db
# La app no corre como root dentro del contenedor
RUN useradd --create-home --uid 10001 zorryfy && mkdir -p /app/music && chown -R zorryfy /app/music
USER zorryfy
ENV PYTHONUNBUFFERED=1
ENV MUSIC_ROOT=/app/music
ENV SCAN_ON_STARTUP=false
ENV SERVE_FRONTEND=false
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"
# --proxy-headers: detrás de Nginx, la IP real del usuario llega en X-Forwarded-For
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
