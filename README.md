# Port Scanner

Este proyecto es un scanner de puertos escrito en Python que utiliza la librería nmap para realizar el escaneo. 

## Instalación

1. Clona el repositorio del proyecto:

```bash
git clone https://github.com/FacundoMajda/tinyscanner.git
```

2. Navega al directorio del proyecto:

```bash
cd tinyscanner
```

3. Instala las dependencias del proyecto:

```bash
pip install -r requirements.txt
```

## Uso

1. Abre el archivo `src/main.py` en un editor de código.

2. Configura los parámetros de escaneo, como la dirección IP a escanear y los puertos a verificar.

3. Ejecuta el archivo `main.py` para iniciar el escaneo de puertos:

```bash
python src/main.py
```

4. La aplicación mostrará la dirección IP, si está activa o no, el protocolo utilizado y los puertos escaneados y si están abiertos.