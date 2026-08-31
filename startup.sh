#!/bin/bash
set -e

cd /home/site/repository/soc_project

python manage.py migrate --no-input
python manage.py collectstatic --no-input

# Worker de tareas en background (Track 5 — django-q2, broker ORM sin Redis).
# Requiere "Always On" activado en Azure App Service para no dormirse con la app.
python manage.py qcluster &

gunicorn soc_project.wsgi:application --bind 0.0.0.0:8000 --workers 2 --timeout 120
