#!/usr/bin/env bash
# build.sh — Render build script
# Called on every deploy. Must be idempotent.

set -o errexit  # exit on error

echo "==> Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Collecting static files..."
python manage.py collectstatic --noinput

echo "==> Running database migrations..."
python manage.py migrate --noinput

echo "==> Build complete."
