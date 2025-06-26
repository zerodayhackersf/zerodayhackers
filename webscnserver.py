#!/usr/bin/env python3
import argparse
import requests
import dns.resolver
import socket
import whois
import shodan
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import json
import time
from datetime import datetime

class SpiderFootTerminal:
    def __init__(self, target, shodan_key=None):
        self.target = target
        self.shodan_key = shodan_key
        self.results = {
            'dns': {},
            'whois': {},
            'web': {},
            'shodan': {},
            'subdomains': [],
            'metadata': {}
        }
        
    def run_all(self):
        print(f"[*] Starting reconnaissance on {self.target}")
        start_time = time.time()
        
        self.results['metadata']['start_time'] = datetime.now().isoformat()
        self.results['metadata']['target'] = self.target
        
        print("[*] Running DNS lookups...")
        self.dns_lookup()
        
        print("[*] Running WHOIS lookup...")
        self.whois_lookup()
        
        print("[*] Scanning website...")
        self.web_scan()
        
        if self.shodan_key:
            print("[*] Querying Shodan...")
            self.shodan_lookup()
        else:
            print("[!] No Shodan API key provided, skipping Shodan lookup")
            
        print("[*] Searching for subdomains...")
        self.find_subdomains()
        
        self.results['metadata']['end_time'] = datetime.now().isoformat()
        self.results['metadata']['duration'] = time.time() - start_time
        
        print("\n[+] Reconnaissance complete!")
        return self.results
    
    def dns_lookup(self):
        try:
            # A record
            answers = dns.resolver.resolve(self.target, 'A')
            self.results['dns']['a_records'] = [str(r) for r in answers]
            
            # MX records
            try:
                answers = dns.resolver.resolve(self.target, 'MX')
                self.results['dns']['mx_records'] = [str(r) for r in answers]
            except:
                pass
                
            # NS records
            try:
                answers = dns.resolver.resolve(self.target, 'NS')
                self.results['dns']['ns_records'] = [str(r) for r in answers]
            except:
                pass
                
            # TXT records
            try:
                answers = dns.resolver.resolve(self.target, 'TXT')
                self.results['dns']['txt_records'] = [str(r) for r in answers]
            except:
                pass
                
        except Exception as e:
            self.results['dns']['error'] = str(e)
    
    def whois_lookup(self):
        try:
            w = whois.whois(self.target)
            self.results['whois'] = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country
            }
        except Exception as e:
            self.results['whois']['error'] = str(e)
    
    def web_scan(self):
        try:
            url = f"http://{self.target}" if not self.target.startswith(('http://', 'https://')) else self.target
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            headers = {
                'User-Agent': 'SpiderFootTerminal/1.0'
            }
            
            # Get homepage
            response = requests.get(base_url, headers=headers, timeout=10)
            self.results['web']['status_code'] = response.status_code
            self.results['web']['headers'] = dict(response.headers)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            links = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    links.add(href)
                elif href.startswith('/'):
                    links.add(base_url + href)
            self.results['web']['links'] = list(links)
            
            # Extract meta tags
            meta_tags = {}
            for tag in soup.find_all('meta'):
                if tag.get('name'):
                    meta_tags[tag.get('name')] = tag.get('content')
                elif tag.get('property'):
                    meta_tags[tag.get('property')] = tag.get('content')
            self.results['web']['meta_tags'] = meta_tags
            
            # Extract titles
            self.results['web']['title'] = soup.title.string if soup.title else None
            
        except Exception as e:
            self.results['web']['error'] = str(e)
    
    def shodan_lookup(self):
        try:
            api = shodan.Shodan(self.shodan_key)
            
            # Host lookup
            host = api.host(self.target)
            self.results['shodan'] = {
                'ip': host.get('ip_str'),
                'org': host.get('org'),
                'os': host.get('os'),
                'ports': host.get('ports'),
                'vulns': host.get('vulns'),
                'hostnames': host.get('hostnames'),
                'data': []
            }
            
            for item in host.get('data', []):
                self.results['shodan']['data'].append({
                    'port': item.get('port'),
                    'banner': item.get('data'),
                    'product': item.get('product'),
                    'version': item.get('version')
                })
                
        except shodan.APIError as e:
            self.results['shodan']['error'] = str(e)
        except Exception as e:
            self.results['shodan']['error'] = str(e)
    
    def find_subdomains(self):
        try:
            # Use common subdomain list
            common_subdomains = [
                'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'blog', 'dev', 'test', 'admin', 'secure', 'portal', 'cpanel',
                'webdisk', 'whm', 'autodiscover', 'm', 'mobile', 'api'
            ]
            
            found_subdomains = []
            
            for sub in common_subdomains:
                full_domain = f"{sub}.{self.target}"
                try:
                    socket.gethostbyname(full_domain)
                    found_subdomains.append(full_domain)
                except socket.gaierror:
                    continue
            
            self.results['subdomains'] = found_subdomains
            
        except Exception as e:
            self.results['subdomains_error'] = str(e)
    
    def save_results(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="SpiderFoot Terminal - OSINT Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-o", "--output", help="Output file to save results (JSON format)")
    parser.add_argument("--shodan", help="Shodan API key (for additional data)")
    
    args = parser.parse_args()
    
    sf = SpiderFootTerminal(args.target, args.shodan)
    results = sf.run_all()
    
    if args.output:
        sf.save_results(args.output)
    else:
        print("\n=== Results ===")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()