FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV DLP_ENV=production DB_PATH=/var/data/dlp.db
RUN mkdir -p /var/data
EXPOSE 8000
# access log format omits query strings so search text can never reach logs
CMD ["sh","-c","gunicorn -w 2 -b 0.0.0.0:${PORT:-8000} --access-logformat '%(h)s \"%(m)s %(U)s\" %(s)s' wsgi:app"]
