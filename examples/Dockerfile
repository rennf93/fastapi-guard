FROM python:3.10-slim

WORKDIR /app

COPY examples/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY guard/ /app/guard/
COPY examples/main.py /app/

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
