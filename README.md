# DNS IP Redirector con Bloques Configurables

Este proyecto implementa un servicio DNS que intercepta respuestas que contienen ciertas direcciones IP y las redirecciona a IPs destino configurables, con soporte para bloques de IPs con redirección aleatoria.

## Características

- Redirección de bloques de IPs a grupos de IPs destino configurable
- Selección aleatoria de IP destino dentro de cada bloque para balancear carga
- Procesamiento eficiente con múltiples hilos
- Fácil despliegue usando Docker y Docker Compose
- Configuración mediante archivos y variables de entorno
- Recarga dinámica de configuración sin reiniciar el servicio

## Estructura del Proyecto
.
├── dns-redirector.go    # Código principal en Go
├── Dockerfile           # Instrucciones para construir la imagen Docker
├── docker-compose.yml   # Configuración de Docker Compose
├── entrypoint.sh        # Script de inicio para el contenedor
├── go.mod               # Dependencias de Go
├── go.sum               # Verificación de dependencias
├── ip_blocks.txt        # Configuración de bloques de IPs
├── config.txt           # Configuración general
└── README.md            # Este archivo
