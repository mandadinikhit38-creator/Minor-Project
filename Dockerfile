FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
COPY requirements-ml.txt .
ARG INSTALL_ML=false
RUN if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir -r requirements-ml.txt; else pip install --no-cache-dir -r requirements.txt; fi
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
