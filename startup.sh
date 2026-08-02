#!/bin/bash
set -e

cd /home/site/repository/soc_project

python manage.py migrate --no-input
python manage.py collectstatic --no-input

gunicorn soc_project.wsgi:application --bind 0.0.0.0:8000 --workers 2 --timeout 120
