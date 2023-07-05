#!/bin/sh

python manage.py flush --no-input  # clearing out the database (for development db)
python manage.py makemigrations
python manage.py migrate

exec "$@"