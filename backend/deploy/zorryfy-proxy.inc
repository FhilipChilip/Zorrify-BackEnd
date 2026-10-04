# Reenvío común hacia el contenedor de la API
proxy_pass http://zorryfy:8000;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
# Streaming con Range: sin buffer para que adelantar/retroceder sea inmediato
proxy_buffering off;
proxy_read_timeout 300s;
