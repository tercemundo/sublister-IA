import requests
import dns.resolver
import concurrent.futures
import argparse
from datetime import datetime
import json
import re
from bs4 import BeautifulSoup
import sys

class AdvancedSubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def search_crt_sh(self):
        """Busca subdominios usando certificates de crt.sh"""
        print("[*] Buscando en crt.sh...")
        try:
            url = f'https://crt.sh/?q=%.{self.domain}&output=json'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry['name_value'].lower()
                    subdomains = re.findall(rf'[a-zA-Z0-9._-]+\.{self.domain}', name_value)
                    self.subdomains.update(subdomains)
        except Exception as e:
            print(f"[!] Error en búsqueda crt.sh: {str(e)}")

    def search_virustotal(self, api_key):
        """Busca subdominios usando la API de VirusTotal"""
        if not api_key:
            return

        print("[*] Buscando en VirusTotal...")
        try:
            url = f'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey': api_key, 'domain': self.domain}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    self.subdomains.update(data['subdomains'])
        except Exception as e:
            print(f"[!] Error en búsqueda VirusTotal: {str(e)}")

    def search_wayback(self):
        """Busca subdominios en Wayback Machine"""
        print("[*] Buscando en Wayback Machine...")
        try:
            url = f'http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                for item in data[1:]:  # Skip header row
                    subdomain = re.findall(rf'[a-zA-Z0-9._-]+\.{self.domain}', item[2])
                    self.subdomains.update(subdomain)
        except Exception as e:
            print(f"[!] Error en búsqueda Wayback: {str(e)}")

    def search_dns_dumpster(self):
        """Busca subdominios en DNSDumpster"""
        print("[*] Buscando en DNSDumpster...")
        try:
            url = f'https://dnsdumpster.com/'
            session = requests.Session()
            response = session.get(url)
            csrf_token = re.findall(fr"name='csrfmiddlewaretoken' value='(.*?)'", response.text)[0]

            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain,
            }
            headers = {
                'Referer': url,
                **self.headers
            }

            response = session.post(url, data=data, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                tables = soup.find_all('table')
                for table in tables:
                    subdomains = re.findall(rf'[a-zA-Z0-9._-]+\.{self.domain}', str(table))
                    self.subdomains.update(subdomains)
        except Exception as e:
            print(f"[!] Error en búsqueda DNSDumpster: {str(e)}")

    def check_wildcard_dns(self):
        """Verifica si el dominio usa wildcard DNS"""
        random_subdomain = f'wildcard_test_123_{datetime.now().strftime("%Y%m%d%H%M%S")}'
        try:
            self.resolver.resolve(f'{random_subdomain}.{self.domain}', 'A')
            return True
        except:
            return False

    def verify_subdomain(self, subdomain):
        """Verifica si un subdominio está activo"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(answer) for answer in answers]
            try:
                answers_mx = self.resolver.resolve(subdomain, 'MX')
                mx_records = [str(answer.exchange) for answer in answers_mx]
            except:
                mx_records = []

            return {
                'subdomain': subdomain,
                'ips': ips,
                'mx_records': mx_records,
                'status': 'active'
            }
        except:
            return None

    def perform_scan(self, virustotal_api_key=None):
        print(f"\n[*] Iniciando escaneo avanzado para: {self.domain}")
        print("[*] Fecha y hora de inicio:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Verificar wildcard DNS
        if self.check_wildcard_dns():
            print("[!] Advertencia: Detectado Wildcard DNS")

        # Realizar búsquedas en diferentes fuentes
        self.search_crt_sh()
        self.search_wayback()
        self.search_dns_dumpster()
        if virustotal_api_key:
            self.search_virustotal(virustotal_api_key)

        print(f"\n[*] Encontrados {len(self.subdomains)} subdominios únicos")
        print("[*] Verificando subdominios activos...")

        # Verificar subdominios encontrados
        verified_subdomains = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(self.verify_subdomain, subdomain): subdomain
                                 for subdomain in self.subdomains}

            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    verified_subdomains.append(result)

        # Ordenar resultados
        verified_subdomains.sort(key=lambda x: x['subdomain'])

        print("\n[+] Resultados:")
        for result in verified_subdomains:
            print(f"\nSubdominio: {result['subdomain']}")
            print(f"IPs: {', '.join(result['ips'])}")
            if result['mx_records']:
                print(f"MX Records: {', '.join(result['mx_records'])}")

        print(f"\n[*] Total de subdominios activos encontrados: {len(verified_subdomains)}")
        print("[*] Fecha y hora de finalización:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        return verified_subdomains

def main():
    parser = argparse.ArgumentParser(description='Herramienta Avanzada de Búsqueda de Subdominios')
    parser.add_argument('domain', help='Dominio a escanear')
    parser.add_argument('-o', '--output', help='Archivo de salida (JSON)')
    parser.add_argument('-v', '--virustotal-api-key', help='API Key de VirusTotal')
    args = parser.parse_args()

    finder = AdvancedSubdomainFinder(args.domain)
    results = finder.perform_scan(args.virustotal_api_key)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
            print(f"\n[*] Resultados guardados en: {args.output}")

if __name__ == '__main__':
    main()
