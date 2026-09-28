FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY monitor ./monitor
# Defensa en profundidad: usuario sin privilegios
RUN useradd -r -u 10001 mgm && mkdir -p /data/logs /data/canary && chown -R mgm /data
USER mgm
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app.helpdesk:wsgi()"]
