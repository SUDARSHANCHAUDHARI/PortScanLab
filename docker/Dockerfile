FROM python:3.12-slim

WORKDIR /app
COPY . .

CMD ["python", "-m", "src.timeline", "data/normal-traffic.log", "data/nmap-scan.log"]
