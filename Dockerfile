# ============================================================================
# PROJECT: VigilantLedger
# FILE: Dockerfile
# DESCRIPTION: Unified container image containing SQL Server 2022 and python
#              FastAPI backend, optimized for Hugging Face Spaces (UID 1000).
# ============================================================================

FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install core build dependencies, python3, and unixodbc
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    apt-transport-https \
    python3 \
    python3-pip \
    unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

# Add Microsoft repository keys for SQL Server 2022
RUN curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-archive-keyring.gpg
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/ubuntu/22.04/mssql-server-2022 jammy main" | tee /etc/apt/sources.list.d/mssql-server-2022.list

# Install Microsoft SQL Server 2022
RUN apt-get update && ACCEPT_EULA=Y apt-get install -y mssql-server

# Install Microsoft ODBC Driver 18 for SQL Server (essential for pyodbc)
RUN curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list | tee /etc/apt/sources.list.d/mssql-release.list
RUN apt-get update && ACCEPT_EULA=Y apt-get install -y msodbcsql18

# Set up project workspace
WORKDIR /code
COPY requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source files
COPY . /code

# Configure permissions for rootless container runtimes (like Hugging Face)
RUN mkdir -p /var/opt/mssql && chmod -R 777 /var/opt/mssql /etc/passwd

# Hugging Face Spaces defaults to exposing port 7860
EXPOSE 7860

# Grant execute rights to bootstrap script
RUN chmod +x /code/start.sh

# Run startup orchestrator
CMD ["/code/start.sh"]
