import nmap

def get_ip():
    """Solicita al usuario que ingrese una dirección IP."""
    ip = input("Ingrese direccion IP: ")
    return ip

def scan_ip(ip):
    """Escanea la IP utilizando nmap y devuelve el objeto scanner."""
    try:

        nm = nmap.PortScanner()


    # Argumentos del escaneo:
    # -sS: Realiza un escaneo de tipo SYN (half-open) para determinar los puertos abiertos.
    # -n: Deshabilita la resolución de nombres DNS para las direcciones IP encontradas.
    # -Pn: Ignora la detección de hosts y realiza el escaneo incluso si el host parece estar inactivo.
    # -T4: Establece el nivel de agresividad del escaneo en 4, lo que significa un escaneo rápido y más agresivo.

    # Realizar el escaneo utilizando los argumentos especificados
        nm.scan(ip, arguments="-sS -n -Pn -T4")
        return nm
    except nmap.PortScannerError:
        print("Nmap no se encontró, por favor instale nmap en su sistema.")
        return None
    except Exception as e:
        print("Ocurrió un error inesperado: ", e)
        return None

def get_scan_results(nm, ip):
    """Imprime los resultados del escaneo y devuelve los puertos abiertos si los hay."""
    results = nm[ip]
    
    if results.state() == "up":
        print("Host : {}".format(ip))
        print("Estado : {}".format(results.state()))

        puertos_abiertos = []
        for proto in results.all_protocols():
            print("Protocolo : {}".format(proto))

            lport = sorted(results[proto].keys())
            for port in lport:
                print ("[*] PUERTO : {}\tstate : {}".format(port, results[proto][port]['state']))
                if results[proto][port]['state'] == 'open':
                    puertos_abiertos.append(port)

        if puertos_abiertos:
            print("Puertos abiertos: {}".format(", ".join(map(str, puertos_abiertos))))
            return puertos_abiertos
        else:
            print("No hay puertos abiertos.")
            return None
    else:
        print("El host está inactivo.")
        return None

def use_ports(ports):
    """Función que aprovecha los puertos abiertos."""
    pass