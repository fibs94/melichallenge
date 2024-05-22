# Packet Analyzer

Packet Analyzer es una aplicación que captura paquetes de red, los analiza y muestra estadísticas en la consola. Utiliza `scapy` para la captura de paquetes y `sqlite3` para almacenar los datos capturados.

## Requisitos

- Docker

## Configuración

### Paso 1: Clonar el repositorio

Clona el repositorio en tu dispositivo local.

```bash
git clone https://github.com/fibs94/melichallenge.git
cd melichallenge
```

### Paso 2: Construir la imagen Docker

Construye la imagen Docker utilizando el archivo Dockerfile incluido en el repositorio.

```bash
docker build -t packet_analyzer .
```

### Paso 3: Ejecutar el contenedor Docker

Ejecuta el contenedor Docker en segundo plano.

```bash
docker run -d --name packet_analyzer --net=host packet_analyzer
```

## Uso

La aplicación captura paquetes en la interfaz de red cada 5 segundos y muestra las estadísticas en la consola. Las estadísticas incluyen:

- Fecha y hora del análisis.
- Tiempo de ejecución de la aplicación.
- Total de paquetes capturados desde el inicio.
- Total de paquetes capturados en los últimos 5 segundos.
- Tamaño total de los paquetes en los últimos 5 segundos.
- Paquetes por protocolo (últimos 5 segundos).
- Top 5 IPs de origen con mayor tráfico (últimos 5 segundos).
- Top 5 IPs de destino con mayor tráfico (últimos 5 segundos).

## Archivos incluídos 

- app.py: Script principal de la aplicación.
- Dockerfile: Archivo de configuración para construir la imagen Docker.
- requirements.txt: Lista de dependencias de Python necesarias para la aplicación.

## Ejemplo de ejecución

```bash
git clone https://github.com/fibs94/melichallenge.git
cd melichallenge
docker build -t packet_analyzer .
docker run -d --name packet_analyzer --net=host packet_analyzer
```
