# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    dnsutils \
    curl \
    libpq-dev \  # Install PostgreSQL client library
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project
COPY . .

# Ensure log and results directories exist
RUN mkdir -p logs config results

# Expose the port the app runs on
EXPOSE 5000

# Define environment variables for configuration
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV REDIS_DB=0
ENV DOMAIN_REPUTATION_API_URL=https://api.domain-reputation.com/check
ENV SPAM_TRAP_FILE=config/spam_traps.txt
ENV CELERY_BROKER_URL=redis://redis:6379/0
ENV CELERY_RESULT_BACKEND=redis://redis:6379/0
ENV DATABASE_URI=postgresql+psycopg2://username:password@db:5432/email_validation_db

# Health check to ensure the API is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/validate || exit 1

# Define the default command
CMD ["python", "app/core_application.py"]