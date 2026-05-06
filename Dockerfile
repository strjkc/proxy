FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY requirements.txt ./
COPY src/ ./src
RUN pip install -r requirements.txt && pip install .
EXPOSE 8181
CMD ["python", "-m", "proxy.main"]
