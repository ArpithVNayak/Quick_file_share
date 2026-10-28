FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
ENV DATA_DIR=/data
VOLUME /data
CMD ["sh","-c","gunicorn -b 0.0.0.0:${PORT:-5000} app:app"]
