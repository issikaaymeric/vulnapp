FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# vuln.db is created at container start by app.py's init_db() if absent.
# Not baking it into the image keeps `docker compose down -v` a clean reset.

EXPOSE 5000

CMD ["python", "app.py"]