import nmap
import json
import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor

class PortExploitScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_target(self, target):
        """Realiza un escaneo con nmap usando scripts por defecto"""
        print(f"\n[+] Iniciando escaneo de {target}")
        print("[+] Esto puede tomar algunos minutos...\n")

        try:
            # Escaneo con scripts por defecto y detección de versión
            self.nm.scan(target, arguments='-sV -sC')

            for host in self.nm.all_hosts():
                print(f"Host : {host} ({self.nm[host].hostname()})")
                print(f"Estado : {self.nm[host].state()}")

                for proto in self.nm[host].all_protocols():
                    print(f"\nProtocolo : {proto}")

                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        print(f"\nPuerto : {port}")
                        print(f"Estado : {service['state']}")
                        print(f"Servicio : {service['name']}")
                        print(f"Versión : {service['version']}")
                        print(f"Producto : {service['product']}")

                        # Mostrar resultados de scripts
                        if 'script' in service:
                            print("\nResultados de scripts:")
                            for script_name, script_output in service['script'].items():
                                print(f"{script_name}:")
                                print(f"{script_output}\n")

                        # Buscar exploits potenciales
                        self.search_exploits(service['name'], service['product'], service['version'])

        except Exception as e:
            print(f"Error durante el escaneo: {str(e)}")

    def search_exploits(self, service_name, product, version):
        """Busca exploits relacionados con el servicio"""
        print("\nBuscando exploits potenciales...")

        # Construir query para búsqueda
        search_terms = [term for term in [service_name, product, version] if term and term != ""]
        search_query = " ".join(search_terms)

        try:
            # Buscar en Exploit-DB (ejemplo usando la API pública)
            url = f"https://exploits.shodan.io/api/search?query={search_query}"
            print(f"[*] Exploits potenciales para {search_query}:")
            print("[*] Nota: Verifica manualmente estos exploits en exploit-db.com o rapid7.com")
            print("[*] Referencias sugeridas:")
            print(f"- https://www.exploit-db.com/search?q={search_query}")
            print(f"- https://www.rapid7.com/db/?q={search_query}")

        except Exception as e:
            print(f"Error buscando exploits: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Uso: python script.py <dirección_ip>")
        print("Ejemplo: python script.py 192.168.1.1")
        sys.exit(1)

    scanner = PortExploitScanner()
    scanner.scan_target(sys.argv[1])

if __name__ == "__main__":
    main()
