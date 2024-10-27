FROM python:3.9-slim

# Install necessary build tools and libraries
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    build-essential \
    python3-dev

# Set the working directory
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY . .

# Expose port 8000
EXPOSE 8000

# Run the app using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


