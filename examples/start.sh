#!/bin/bash

pip install -r requirements.txt

uvicorn main:app --host 0.0.0.0 --port 8080 --reload --ssl-keyfile ./cert/private.key --ssl-certfile ./cert/server.crt
