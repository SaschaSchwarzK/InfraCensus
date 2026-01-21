FROM python:3.12-slim

WORKDIR /app
COPY collector ./collector

CMD ["python", "collector/agent/main.py"]
