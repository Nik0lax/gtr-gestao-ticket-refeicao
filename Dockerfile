FROM python:3.12-bullseye

WORKDIR /app

# instalar dependências + wkhtmltopdf + bibliotecas do WeasyPrint (cabeçalho/rodapé dos relatórios em PDF)
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    wkhtmltopdf \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# --timeout 120: consultas à Salutem e relatórios grandes podem passar dos 30 s padrão do gunicorn
CMD ["gunicorn", "-w", "4", "--timeout", "120", "-b", "0.0.0.0:5000", "app:app"]
