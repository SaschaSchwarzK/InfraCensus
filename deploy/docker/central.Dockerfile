FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY central ./central

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "central.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
