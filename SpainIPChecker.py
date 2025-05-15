import asyncio
import aiohttp
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import ssl
import time
import logging

logging.basicConfig(level=logging.WARNING)
logging.getLogger('aiohttp').setLevel(logging.ERROR)

class IPChecker:
    def __init__(self, domain_file, output_file, html_dir="html_content"):
        self.domain_file = domain_file
        self.output_file = output_file
        self.html_dir = html_dir
        self.domains = []
        self.blocked_count = 0
        self.completed_checks = 0
        self.start_time = None
        
        load_dotenv()
        
        # Build proxy configuration for ES_DigiSpain
        self.proxy_url = self._build_proxy_url()
        
        # Create SSL context
        self.ssl_context = self._create_ssl_context()
        
    def _build_proxy_url(self):
        """Build proxy URL for ES_DigiSpain"""
        username = os.getenv("GEONODE_USERNAME")
        password = os.getenv("GEONODE_PASSWORD")
        proxy_host = os.getenv("PROXY_HOST", "proxy.geonode.io")
        proxy_port = os.getenv("PROXY_PORT", "9000")
        asn = os.getenv("ES_DIGISPAIN_ASN")
        
        if not username or not password:
            print("Warning: GEONODE_USERNAME or GEONODE_PASSWORD not set in .env file")
            return None
            
        return f"http://{username}-type-residential-country-es-asn-{asn}:{password}@{proxy_host}:{proxy_port}"
    
    def _create_ssl_context(self):
        """Create SSL context for flexible TLS version support"""
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.options &= ~ssl.OP_NO_TLSv1
            ssl_context.options &= ~ssl.OP_NO_TLSv1_1
            ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')
            return ssl_context
        except Exception as e:
            print(f"Failed to create custom SSL context: {e}")
            return None
    
    
    def load_domains(self):
        """Load domains from plain text file (one domain per line)"""
        try:
            seen_domains = set()
            
            with open(self.domain_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    if domain and '.' in domain and not domain.startswith('.'):
                        if domain not in seen_domains:
                            self.domains.append(domain)
                            seen_domains.add(domain)
                                
        except Exception as e:
            print(f"Error reading input file: {e}")
            sys.exit(1)
        
        print(f"Loaded {len(self.domains)} unique domains")
    
    async def check_domain(self, session, domain):
        """Check a single domain for blocking with retries"""
        url = f"https://{domain}"
        max_attempts = 3
        
        for attempt in range(1, max_attempts + 1):
            try:
                async with session.get(
                    url, 
                    proxy=self.proxy_url,
                    headers={"User-Agent": "SpainIPChecker/1.0"},
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False,
                    ssl=self.ssl_context
                ) as response:
                    
                    if response.status == 200:
                        html_content = await response.text()

                     # -- ISP BLOCKING CHECK -- 
                        if "https://www.laliga.com/noticias/nota-informativa-en-relacion-con-el-bloqueo-de-ips-durante-las-ultimas-jornadas-de-laliga-ea-sports-vinculadas-a-las-practicas-ilegales-de-cloudflare" in html_content:
                            self.blocked_count += 1
                            
                            # Save HTML content
                            domain_dir = Path(self.html_dir) / domain
                            domain_dir.mkdir(parents=True, exist_ok=True)
                            
                            html_file = domain_dir / f"ES_DigiSpain_attempt{attempt}.html"
                            with open(html_file, 'w', encoding='utf-8') as f:
                                f.write(html_content)
                                
                            return True
                            
            except asyncio.TimeoutError:
                pass
            except aiohttp.ClientError as e:
                pass
            except Exception as e:
                pass
            
            # Wait before retry (except on last attempt)
            if attempt < max_attempts:
                await asyncio.sleep(0.5)
                
        return False
    
    def print_progress(self):
        """Print progress update with visual progress bar"""
        elapsed = time.time() - self.start_time
        progress_percent = (self.completed_checks / len(self.domains)) * 100
        rate = self.completed_checks / elapsed if elapsed > 0 else 0
        eta = (len(self.domains) - self.completed_checks) / rate if rate > 0 else 0
        
        # Create progress bar
        bar_width = 40
        filled_width = int(bar_width * progress_percent / 100)
        bar = "█" * filled_width + "░" * (bar_width - filled_width)
        
        # Print progress bar
        print(f"\r[{bar}] {progress_percent:.1f}% | {self.completed_checks}/{len(self.domains)} | "
              f"Blocks: {self.blocked_count} | {rate:.0f}/sec | ETA: {eta/60:.1f}m", end="")
    
    async def process_domain(self, session, domain, outfile):
        """Process a single domain and write result"""
        is_blocked = await self.check_domain(session, domain)
        
        # Write result
        outfile.write(f"{domain},ES_DigiSpain,{is_blocked}\n")
        
        self.completed_checks += 1
        
        # Print progress
        if time.time() - self.last_progress_time >= 2:
            self.print_progress()
            self.last_progress_time = time.time()
    
    async def run(self):
        """Run the checker"""
        self.start_time = time.time()
        self.last_progress_time = self.start_time
        
        print(f"Starting scan of {len(self.domains)} domains across 1 ISP ({len(self.domains)} total checks)")
        
        # Create HTML directory
        Path(self.html_dir).mkdir(parents=True, exist_ok=True)
        
        # Create output file
        with open(self.output_file, 'w', newline='', encoding='utf-8') as outfile:
            outfile.write(f"domain,isp_name,is_blocked\n")
            
            # Create aiohttp session  
            connector = aiohttp.TCPConnector(
                limit=0,
                limit_per_host=0,
                ssl=self.ssl_context,
                enable_cleanup_closed=True,
                ttl_dns_cache=300
            )
            
            async with aiohttp.ClientSession(connector=connector) as session:
                # Create tasks for all domains
                tasks = []
                for domain in self.domains:
                    tasks.append(self.process_domain(session, domain, outfile))
                
                # Run all tasks with concurrency limit
                semaphore = asyncio.Semaphore(500)
                async def run_with_semaphore(task):
                    async with semaphore:
                        await task
                
                await asyncio.gather(*[run_with_semaphore(task) for task in tasks])
        
        # Print final results
        total_time = time.time() - self.start_time
        rate = len(self.domains) / total_time if total_time > 0 else 0
        
        print("\n\n" + "="*50)
        print(f"SCAN COMPLETE - Total time: {total_time:.1f} seconds")
        print(f"Results saved to: {self.output_file}")
        print(f"Scanned {len(self.domains)} domains with {len(self.domains)} checks")
        print(f"Average speed: {rate:.1f} checks/sec")
        print(f"Blocks found: {self.blocked_count}")
        if self.blocked_count > 0:
            print(f"HTML content saved to: {Path(self.html_dir).absolute()}")
        print("="*50)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 SpainIPChecker.py <domain_file> <output_file>")
        print("  domain_file: plain text file with one domain per line")
        print("  output_file: CSV file for results")
        sys.exit(1)
    
    domain_file = sys.argv[1]
    output_file = sys.argv[2]
    
    checker = IPChecker(domain_file, output_file)
    checker.load_domains()
    
    asyncio.run(checker.run())

if __name__ == "__main__":
    main()
