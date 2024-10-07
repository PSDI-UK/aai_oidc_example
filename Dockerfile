FROM python:3.10.13-slim-bookworm

WORKDIR /app
COPY . /app

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80

CMD ["fastapi", "run", "main.py"]