# Base image with Python 3.10
FROM python:3.10-slim

# Install library from PyPI
RUN pip install fastapi-guard uvicorn

# Copy example FastAPI app using the middleware
COPY example-app/ /app
WORKDIR /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0"]
