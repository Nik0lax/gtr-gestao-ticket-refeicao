FROM python:3.12-bullseye

WORKDIR /app

# instalar dependências + wkhtmltopdf
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
