FROM python:3.8.5-alpine3.12
ADD source /source
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /source
RUN python manage.py makemigrations interface
WORKDIR /source
CMD ["gunicorn", "--workers=1", "--bind", "0.0.0.0:8000", "webapp.wsgi"]