FROM python:3.11-slim

# Install Ruby and WPScan dependencies
RUN apt-get update && apt-get install -y ruby-full build-essential zlib1g-dev libcurl4-openssl-dev && \
    gem install wpscan

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "dns_health_checker.py", "--server.port=8501", "--server.address=0.0.0.0"]
