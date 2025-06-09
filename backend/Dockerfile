FROM python:3.9-slim

WORKDIR /app

# Install system dependencies required for mysqlclient and MySQL client
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    default-mysql-client \
    gcc \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7331

# Start application with entrypoint
CMD ["python", "app.py"] 