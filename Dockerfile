FROM python:3.9-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar los archivos necesarios
COPY app.py ./
COPY requirements.txt ./

# Instalar dependencias y utilidades de terminal
RUN apt-get update && apt-get install -y ncurses-base
RUN pip install --no-cache-dir -r requirements.txt

# Establecer la variable de entorno TERM
ENV TERM xterm

# Comando por defecto
CMD ["python", "app.py"]

