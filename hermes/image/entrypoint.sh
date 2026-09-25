#!/bin/sh
set -eu
umask 077
exec /opt/hermes/.venv/bin/python /opt/hermes-sandbox/supervisor.py
