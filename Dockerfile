# Use official lightweight Python base image
FROM python:3.10-slim

# Set working directory inside container
WORKDIR /app

# Copy all project files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose no port — not needed unless you add a dashboard later

# Default command
CMD ["python", "intrusion_detection_system.py"]
