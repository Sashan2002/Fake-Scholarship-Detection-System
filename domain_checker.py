import requests
import socket
import ssl
import whois
from urllib.parse import urlparse
from datetime import datetime, timedelta
import logging
import dns.resolver
import time
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import warnings
import hashlib
import ipaddress
from typing import Dict, List, Optional, Tuple

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)

class DomainChecker:
    def __init__(self):
        """Initialize the domain checker"""
        self.timeout = 10
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Known legitimate scholarship domains
        self.legitimate_domains = {
            'scholarships.com', 'fastweb.com', 'collegeboard.org', 
            'studentaid.gov', 'cappex.com', 'scholarshipamerica.org',
            'coca-colascholarsfoundation.org', 'gatesfoundation.org',
            'universityschoices.com', 'scholarshipowl.com',
            'nitrogenscholarship.com', 'scholarships360.org',
            'petersons.com', 'unigo.com', 'scholarshipexperts.com',
            'moolahspot.com', 'finaid.org', 'bigfuture.collegeboard.org',
            'scholarshipdirectory.com', 'collegescholarships.org',
            'scholarships4students.com', 'merit.com'
        }
        
        # Known scam indicators in domains
        self.suspicious_patterns = [
            r'free.*money', r'guaranteed.*scholarship', r'instant.*cash',
            r'no.*application', r'winner.*selected', r'claim.*now',
            r'\d+.*million', r'government.*grant', r'federal.*grant',
            r'easy.*money', r'quick.*cash', r'free.*grant',
            r'scholarship.*winner', r'congratulations.*grant',
            r'pre.*approved', r'million.*dollar', r'lottery.*win',
            r'inheritance.*fund', r'beneficiary.*selected',
            r'urgent.*response', r'limited.*time.*offer'
        ]
        
        # Educational domain extensions
        self.edu_extensions = {'.edu', '.ac.uk', '.edu.au', '.ac.nz', '.edu.ca', 
                             '.edu.sg', '.ac.za', '.edu.in', '.ac.in', '.edu.my'}
        
        # Government domain extensions
        self.gov_extensions = {'.gov', '.gov.uk', '.gov.au', '.gov.ca', '.gov.sg'}
        
        # Temporary/suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.win', 
            '.download', '.loan', '.racing', '.review', '.work',
            '.click', '.link', '.buzz', '.website', '.online',
            '.site', '.tech', '.info', '.biz', '.cc'
        }
        
        # High-reputation TLDs
        self.trusted_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.mil'}
        
        # Common phishing keywords
        self.phishing_keywords = [
            'verify', 'suspend', 'security', 'alert', 'warning',
            'urgent', 'immediate', 'action', 'required', 'expired',
            'update', 'confirm', 'validate', 'authenticate'
        ]
        
        # Cache for domain checks to improve performance
        self.domain_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def check_domain(self, url: str) -> Dict:
        """Perform comprehensive domain analysis"""
        try:
            if not url or not isinstance(url, str):
                return self._default_domain_features()
            
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if not domain:
                return self._default_domain_features()
            
            # Check cache first
            cache_key = hashlib.md5(domain.encode()).hexdigest()
            if cache_key in self.domain_cache:
                cached_result = self.domain_cache[cache_key]
                if time.time() - cached_result['timestamp'] < self.cache_ttl:
                    logger.debug(f"Using cached result for domain: {domain}")
                    return cached_result['data']
            
            logger.info(f"Checking domain: {domain}")
            
            # Perform various checks in parallel for better performance
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    'whois': executor.submit(self._check_whois, domain),
                    'ssl': executor.submit(self._check_ssl, domain),
                    'dns': executor.submit(self._check_dns, domain),
                    'reputation': executor.submit(self._check_reputation, domain),
                    'security': executor.submit(self._check_security_indicators, domain)
                }
                
                # Collect results with timeout
                results = {}
                for key, future in futures.items():
                    try:
                        results[key] = future.result(timeout=15)
                    except (TimeoutError, Exception) as e:
                        logger.warning(f"Error in {key} check for {domain}: {str(e)}")
                        results[key] = self._default_check_result(key)
            
            # Combine all features
            features = self._combine_domain_features(domain, results)
            
            # Cache the result
            self.domain_cache[cache_key] = {
                'data': features,
                'timestamp': time.time()
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error checking domain {url}: {str(e)}")
            return self._default_domain_features()
    
    def _check_whois(self, domain: str) -> Dict:
        """Check WHOIS information for domain age and registration details"""
        try:
            # Remove common prefixes
            clean_domain = domain.replace('www.', '').replace('m.', '')
            
            domain_info = whois.whois(clean_domain)
            
            if not domain_info:
                return {'age_days': 0, 'creation_date': None, 'registrar': None, 
                       'expiration_date': None, 'updated_date': None}
            
            # Get creation date
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # Get expiration date
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            # Get updated date
            updated_date = domain_info.updated_date
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            
            # Calculate age
            if creation_date:
                age_days = (datetime.now() - creation_date).days
            else:
                age_days = 0
            
            # Calculate days until expiration
            days_until_expiration = 0
            if expiration_date:
                days_until_expiration = (expiration_date - datetime.now()).days
            
            # Get registrar info
            registrar = domain_info.registrar if hasattr(domain_info, 'registrar') else None
            
            # Get name servers
            name_servers = domain_info.name_servers if hasattr(domain_info, 'name_servers') else []
            if isinstance(name_servers, list):
                name_servers = [str(ns).lower() for ns in name_servers]
            else:
                name_servers = []
            
            return {
                'age_days': max(0, age_days),
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'updated_date': updated_date,
                'days_until_expiration': days_until_expiration,
                'registrar': registrar,
                'name_servers': name_servers
            }
            
        except Exception as e:
            logger.debug(f"WHOIS check failed for {domain}: {str(e)}")
            return {'age_days': 0, 'creation_date': None, 'registrar': None,
                   'expiration_date': None, 'updated_date': None, 
                   'days_until_expiration': 0, 'name_servers': []}
    
    def _check_ssl(self, domain: str) -> Dict:
        """Check SSL certificate information"""
        try:
            # Remove protocol and path
            clean_domain = domain.replace('www.', '')
            
            context = ssl.create_default_context()
            
            with socket.create_connection((clean_domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check if certificate is valid
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    is_valid = not_before <= datetime.now() <= not_after
                    
                    # Get issuer information
                    issuer = dict(x[0] for x in cert['issuer'])
                    organization = issuer.get('organizationName', '')
                    
                    # Get subject information
                    subject = dict(x[0] for x in cert['subject'])
                    common_name = subject.get('commonName', '')
                    
                    # Check for wildcard certificate
                    is_wildcard = common_name.startswith('*.')
                    
                    # Get Subject Alternative Names
                    san_list = []
                    if 'subjectAltName' in cert:
                        san_list = [name[1] for name in cert['subjectAltName']]
                    
                    # Calculate certificate validity period
                    validity_days = (not_after - not_before).days
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    # Check for self-signed certificate
                    is_self_signed = issuer.get('commonName') == subject.get('commonName')
                    
                    return {
                        'has_ssl': True,
                        'is_valid': is_valid,
                        'issuer': organization,
                        'common_name': common_name,
                        'expires': not_after,
                        'issued': not_before,
                        'is_wildcard': is_wildcard,
                        'is_self_signed': is_self_signed,
                        'san_list': san_list,
                        'validity_days': validity_days,
                        'days_until_expiry': days_until_expiry
                    }
                    
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {str(e)}")
            return {
                'has_ssl': False,
                'is_valid': False,
                'issuer': None,
                'common_name': None,
                'expires': None,
                'issued': None,
                'is_wildcard': False,
                'is_self_signed': False,
                'san_list': [],
                'validity_days': 0,
                'days_until_expiry': 0
            }
    
    def _check_dns(self, domain: str) -> Dict:
        """Check DNS records and configuration"""
        try:
            clean_domain = domain.replace('www.', '')
            
            # Check MX records (email)
            mx_records = []
            try:
                mx_result = dns.resolver.resolve(clean_domain, 'MX')
                mx_records = [str(rdata) for rdata in mx_result]
            except:
                pass
            
            # Check A records
            a_records = []
            try:
                a_result = dns.resolver.resolve(clean_domain, 'A')
                a_records = [str(rdata) for rdata in a_result]
            except:
                pass
            
            # Check AAAA records (IPv6)
            aaaa_records = []
            try:
                aaaa_result = dns.resolver.resolve(clean_domain, 'AAAA')
                aaaa_records = [str(rdata) for rdata in aaaa_result]
            except:
                pass
            
            # Check TXT records (SPF, DKIM, etc.)
            txt_records = []
            try:
                txt_result = dns.resolver.resolve(clean_domain, 'TXT')
                txt_records = [str(rdata) for rdata in txt_result]
            except:
                pass
            
            # Check NS records
            ns_records = []
            try:
                ns_result = dns.resolver.resolve(clean_domain, 'NS')
                ns_records = [str(rdata) for rdata in ns_result]
            except:
                pass
            
            # Check CNAME records
            cname_records = []
            try:
                cname_result = dns.resolver.resolve(clean_domain, 'CNAME')
                cname_records = [str(rdata) for rdata in cname_result]
            except:
                pass
            
            # Analyze IP addresses for suspicious patterns
            suspicious_ips = []
            for ip in a_records:
                if self._is_suspicious_ip(ip):
                    suspicious_ips.append(ip)
            
            return {
                'mx_records': mx_records,
                'a_records': a_records,
                'aaaa_records': aaaa_records,
                'txt_records': txt_records,
                'ns_records': ns_records,
                'cname_records': cname_records,
                'has_mx': len(mx_records) > 0,
                'has_spf': any('spf' in record.lower() for record in txt_records),
                'has_dkim': any('dkim' in record.lower() for record in txt_records),
                'has_dmarc': any('dmarc' in record.lower() for record in txt_records),
                'suspicious_ips': suspicious_ips,
                'ip_count': len(a_records)
            }
            
        except Exception as e:
            logger.debug(f"DNS check failed for {domain}: {str(e)}")
            return {
                'mx_records': [], 'a_records': [], 'aaaa_records': [],
                'txt_records': [], 'ns_records': [], 'cname_records': [],
                'has_mx': False, 'has_spf': False, 'has_dkim': False,
                'has_dmarc': False, 'suspicious_ips': [], 'ip_count': 0
            }
    
    def _check_reputation(self, domain: str) -> Dict:
        """Check domain reputation using various indicators"""
        try:
            clean_domain = domain.replace('www.', '')
            
            # Check against known legitimate domains
            is_known_legitimate = any(legit in clean_domain for legit in self.legitimate_domains)
            
            # Check for educational domains
            is_educational = any(clean_domain.endswith(ext) for ext in self.edu_extensions)
            
            # Check for government domains
            is_government = any(clean_domain.endswith(ext) for ext in self.gov_extensions)
            
            # Check for suspicious patterns in domain name
            has_suspicious_pattern = any(
                re.search(pattern, clean_domain, re.IGNORECASE) 
                for pattern in self.suspicious_patterns
            )
            
            # Check for phishing keywords
            has_phishing_keywords = any(
                keyword in clean_domain for keyword in self.phishing_keywords
            )
            
            # Check for suspicious TLD
            has_suspicious_tld = any(clean_domain.endswith(tld) for tld in self.suspicious_tlds)
            
            # Check for trusted TLD
            has_trusted_tld = any(clean_domain.endswith(tld) for tld in self.trusted_tlds)
            
            # Calculate reputation score
            reputation_score = 50  # Base score
            
            if is_known_legitimate:
                reputation_score += 40
            if is_educational:
                reputation_score += 35
            if is_government:
                reputation_score += 30
            if has_trusted_tld:
                reputation_score += 15
            if has_suspicious_pattern:
                reputation_score -= 35
            if has_phishing_keywords:
                reputation_score -= 25
            if has_suspicious_tld:
                reputation_score -= 30
            
            # Check domain length and complexity
            if len(clean_domain) > 50:
                reputation_score -= 15
            elif len(clean_domain) > 30:
                reputation_score -= 10
            
            # Count numbers and hyphens (often suspicious)
            num_count = sum(c.isdigit() for c in clean_domain)
            hyphen_count = clean_domain.count('-')
            
            if num_count > 5:
                reputation_score -= 15
            elif num_count > 3:
                reputation_score -= 10
            
            if hyphen_count > 3:
                reputation_score -= 15
            elif hyphen_count > 2:
                reputation_score -= 10
            
            # Check for homograph attacks (similar looking characters)
            has_homograph = self._check_homograph_attack(clean_domain)
            if has_homograph:
                reputation_score -= 20
            
            reputation_score = max(0, min(100, reputation_score))
            
            return {
                'reputation_score': reputation_score,
                'is_known_legitimate': is_known_legitimate,
                'is_educational': is_educational,
                'is_government': is_government,
                'has_suspicious_pattern': has_suspicious_pattern,
                'has_phishing_keywords': has_phishing_keywords,
                'has_suspicious_tld': has_suspicious_tld,
                'has_trusted_tld': has_trusted_tld,
                'has_homograph': has_homograph,
                'domain_complexity': self._calculate_domain_complexity(clean_domain)
            }
            
        except Exception as e:
            logger.debug(f"Reputation check failed for {domain}: {str(e)}")
            return {
                'reputation_score': 50, 'is_known_legitimate': False,
                'is_educational': False, 'is_government': False,
                'has_suspicious_pattern': False, 'has_phishing_keywords': False,
                'has_suspicious_tld': False, 'has_trusted_tld': False,
                'has_homograph': False, 'domain_complexity': 1.0
            }
    
    def _check_security_indicators(self, domain: str) -> Dict:
        """Check additional security indicators"""
        try:
            clean_domain = domain.replace('www.', '')
            
            # Check for URL shorteners
            url_shorteners = [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
            ]
            is_url_shortener = any(shortener in clean_domain for shortener in url_shorteners)
            
            # Check for recently registered domains (potential red flag)
            whois_data = self._check_whois(clean_domain)
            is_recently_registered = whois_data['age_days'] < 30
            
            # Check for domain parking
            is_parked = self._check_domain_parking(clean_domain)
            
            # Check for suspicious port usage
            suspicious_ports = self._check_suspicious_ports(clean_domain)
            
            # Generate security score
            security_score = 100
            
            if is_url_shortener:
                security_score -= 30
            if is_recently_registered:
                security_score -= 25
            if is_parked:
                security_score -= 40
            if suspicious_ports:
                security_score -= 20
            
            security_score = max(0, security_score)
            
            return {
                'security_score': security_score,
                'is_url_shortener': is_url_shortener,
                'is_recently_registered': is_recently_registered,
                'is_parked': is_parked,
                'suspicious_ports': suspicious_ports,
                'has_security_issues': security_score < 70
            }
            
        except Exception as e:
            logger.debug(f"Security check failed for {domain}: {str(e)}")
            return {
                'security_score': 75, 'is_url_shortener': False,
                'is_recently_registered': False, 'is_parked': False,
                'suspicious_ports': [], 'has_security_issues': False
            }
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private IP ranges (shouldn't be public-facing)
            if ip_obj.is_private:
                return True
            
            # Check for localhost
            if ip_obj.is_loopback:
                return True
            
            # Check for reserved ranges
            if ip_obj.is_reserved:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _check_homograph_attack(self, domain: str) -> bool:
        """Check for potential homograph attacks"""
        try:
            # Common homograph patterns
            suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
            
            for char in suspicious_chars:
                if char in domain:
                    return True
            
            # Check for mixed scripts
            has_latin = any(ord(c) < 128 for c in domain)
            has_non_latin = any(ord(c) >= 128 for c in domain)
            
            return has_latin and has_non_latin
            
        except Exception:
            return False
    
    def _calculate_domain_complexity(self, domain: str) -> float:
        """Calculate domain complexity score"""
        try:
            # Factors that increase complexity (suspicious)
            score = 1.0
            
            # Length factor
            if len(domain) > 20:
                score += 0.5
            
            # Number of subdomains
            subdomain_count = domain.count('.') - 1
            score += subdomain_count * 0.3
            
            # Special characters
            special_chars = sum(1 for c in domain if not c.isalnum() and c != '.' and c != '-')
            score += special_chars * 0.4
            
            # Consecutive numbers
            consecutive_nums = len(re.findall(r'\d{3,}', domain))
            score += consecutive_nums * 0.6
            
            return min(score, 5.0)
            
        except Exception:
            return 1.0
    
    def _check_domain_parking(self, domain: str) -> bool:
        """Check if domain appears to be parked"""
        try:
            # This is a simplified check - in production, you might want to
            # actually fetch the page content and look for parking indicators
            parking_indicators = [
                'parked', 'domain-for-sale', 'sedo', 'hugedomains',
                'afternic', 'domainnameshop'
            ]
            
            return any(indicator in domain.lower() for indicator in parking_indicators)
            
        except Exception:
            return False
    
    def _check_suspicious_ports(self, domain: str) -> List[int]:
        """Check for suspicious port usage"""
        suspicious_ports = []
        common_suspicious_ports = [8080, 8888, 3128, 1080, 8000, 9999]
        
        for port in common_suspicious_ports:
            try:
                with socket.create_connection((domain, port), timeout=2):
                    suspicious_ports.append(port)
            except:
                continue
        
        return suspicious_ports
    
    def _combine_domain_features(self, domain: str, check_results: Dict) -> Dict:
        """Combine all domain check results into feature vector"""
        try:
            whois_data = check_results.get('whois', {})
            ssl_data = check_results.get('ssl', {})
            dns_data = check_results.get('dns', {})
            reputation_data = check_results.get('reputation', {})
            security_data = check_results.get('security', {})
            
            # Extract features for ML model
            features = {
                # Age and registration features
                'domain_age_days': whois_data.get('age_days', 0),
                'days_until_expiration': whois_data.get('days_until_expiration', 0),
                'domain_registrar': whois_data.get('registrar', ''),
                
                # SSL features
                'ssl_certificate': 1 if ssl_data.get('has_ssl', False) else 0,
                'ssl_valid': 1 if ssl_data.get('is_valid', False) else 0,
                'ssl_issuer': ssl_data.get('issuer', ''),
                'ssl_wildcard': 1 if ssl_data.get('is_wildcard', False) else 0,
                'ssl_self_signed': 1 if ssl_data.get('is_self_signed', False) else 0,
                'ssl_days_until_expiry': ssl_data.get('days_until_expiry', 0),
                
                # DNS features
                'has_mx_records': 1 if dns_data.get('has_mx', False) else 0,
                'has_spf_record': 1 if dns_data.get('has_spf', False) else 0,
                'has_dkim_record': 1 if dns_data.get('has_dkim', False) else 0,
                'has_dmarc_record': 1 if dns_data.get('has_dmarc', False) else 0,
                'mx_count': len(dns_data.get('mx_records', [])),
                'ip_count': dns_data.get('ip_count', 0),
                'suspicious_ip_count': len(dns_data.get('suspicious_ips', [])),
                
                # Reputation features
                'domain_reputation': reputation_data.get('reputation_score', 50),
                'is_educational': 1 if reputation_data.get('is_educational', False) else 0,
                'is_government': 1 if reputation_data.get('is_government', False) else 0,
                'is_known_legitimate': 1 if reputation_data.get('is_known_legitimate', False) else 0,
                'has_suspicious_pattern': 1 if reputation_data.get('has_suspicious_pattern', False) else 0,
                'has_phishing_keywords': 1 if reputation_data.get('has_phishing_keywords', False) else 0,
                'has_suspicious_tld': 1 if reputation_data.get('has_suspicious_tld', False) else 0,
                'has_trusted_tld': 1 if reputation_data.get('has_trusted_tld', False) else 0,
                'has_homograph': 1 if reputation_data.get('has_homograph', False) else 0,
                'domain_complexity': reputation_data.get('domain_complexity', 1.0),
                
                # Security features
                'security_score': security_data.get('security_score', 75),
                'is_url_shortener': 1 if security_data.get('is_url_shortener', False) else 0,
                'is_recently_registered': 1 if security_data.get('is_recently_registered', False) else 0,
                'is_parked': 1 if security_data.get('is_parked', False) else 0,
                'suspicious_port_count': len(security_data.get('suspicious_ports', [])),
                'has_security_issues': 1 if security_data.get('has_security_issues', False) else 0,
                
                # Additional computed features
                'domain_length': len(domain),
                'subdomain_count': domain.count('.') - 1,
                'contains_numbers': 1 if any(c.isdigit() for c in domain) else 0,
                'contains_hyphens': 1 if '-' in domain else 0,
                'number_count': sum(c.isdigit() for c in domain),
                'hyphen_count': domain.count('-'),
                
                # Legacy features for compatibility
                'domain_age': self._format_domain_age(whois_data.get('age_days', 0)),
                'contact_info_present': 1 if dns_data.get('has_mx', False) else 0,
                'social_media_links': 0,  # Would need content analysis
                'privacy_policy_present': 0,  # Would need content analysis
                'legitimacy_indicators': self._calculate_legitimacy_score(
                    reputation_data, security_data, ssl_data, dns_data
                )
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error combining domain features: {str(e)}")
            return self._default_domain_features()
    
    def _format_domain_age(self, age_days: int) -> str:
        """Format domain age for display"""
        if age_days == 0:
            return "Unknown"
        elif age_days < 30:
            return f"{age_days} days"
        elif age_days < 365:
            months = age_days // 30
            return f"{months} month{'s' if months != 1 else ''}"
        else:
            years = age_days // 365
            return f"{years} year{'s' if years != 1 else ''}"
    
    def _calculate_legitimacy_score(self, reputation_data: Dict, security_data: Dict, 
                                  ssl_data: Dict, dns_data: Dict) -> int:
        """Calculate overall legitimacy score (0-100)"""
        try:
            score = 0
            
            # Reputation indicators (40% weight)
            reputation_score = reputation_data.get('reputation_score', 50)
            score += reputation_score * 0.4
            
            # Security indicators (30% weight)
            security_score = security_data.get('security_score', 75)
            score += security_score * 0.3
            
            # SSL indicators (20% weight)
            if ssl_data.get('has_ssl', False):
                score += 15
            if ssl_data.get('is_valid', False):
                score += 5
            
            # DNS indicators (10% weight)
            if dns_data.get('has_mx', False):
                score += 5
            if dns_data.get('has_spf', False):
                score += 3
            if dns_data.get('has_dkim', False):
                score += 2

            return int(min(100, max(0, score)))

        except Exception as e:
            logger.debug(f"Failed to calculate legitimacy score: {str(e)}")
            return 50  # default

    def _default_check_result(self, key: str) -> Dict:
        """Return a safe default result for each component"""
        defaults = {
            'whois': {
                'age_days': 0, 'creation_date': None, 'expiration_date': None,
                'updated_date': None, 'days_until_expiration': 0,
                'registrar': None, 'name_servers': []
            },
            'ssl': {
                'has_ssl': False, 'is_valid': False, 'issuer': None,
                'common_name': None, 'expires': None, 'issued': None,
                'is_wildcard': False, 'is_self_signed': False,
                'san_list': [], 'validity_days': 0, 'days_until_expiry': 0
            },
            'dns': {
                'mx_records': [], 'a_records': [], 'aaaa_records': [],
                'txt_records': [], 'ns_records': [], 'cname_records': [],
                'has_mx': False, 'has_spf': False, 'has_dkim': False,
                'has_dmarc': False, 'suspicious_ips': [], 'ip_count': 0
            },
            'reputation': {
                'reputation_score': 50, 'is_known_legitimate': False,
                'is_educational': False, 'is_government': False,
                'has_suspicious_pattern': False, 'has_phishing_keywords': False,
                'has_suspicious_tld': False, 'has_trusted_tld': False,
                'has_homograph': False, 'domain_complexity': 1.0
            },
            'security': {
                'security_score': 75, 'is_url_shortener': False,
                'is_recently_registered': False, 'is_parked': False,
                'suspicious_ports': [], 'has_security_issues': False
            }
        }
        return defaults.get(key, {})

    def _default_domain_features(self) -> Dict:
        """Return a complete safe fallback feature set"""
        return {
            'domain_age_days': 0,
            'days_until_expiration': 0,
            'domain_registrar': '',
            'ssl_certificate': 0,
            'ssl_valid': 0,
            'ssl_issuer': '',
            'ssl_wildcard': 0,
            'ssl_self_signed': 0,
            'ssl_days_until_expiry': 0,
            'has_mx_records': 0,
            'has_spf_record': 0,
            'has_dkim_record': 0,
            'has_dmarc_record': 0,
            'mx_count': 0,
            'ip_count': 0,
            'suspicious_ip_count': 0,
            'domain_reputation': 50,
            'is_educational': 0,
            'is_government': 0,
            'is_known_legitimate': 0,
            'has_suspicious_pattern': 0,
            'has_phishing_keywords': 0,
            'has_suspicious_tld': 0,
            'has_trusted_tld': 0,
            'has_homograph': 0,
            'domain_complexity': 1.0,
            'security_score': 75,
            'is_url_shortener': 0,
            'is_recently_registered': 0,
            'is_parked': 0,
            'suspicious_port_count': 0,
            'has_security_issues': 0,
            'domain_length': 0,
            'subdomain_count': 0,
            'contains_numbers': 0,
            'contains_hyphens': 0,
            'number_count': 0,
            'hyphen_count': 0,
            'domain_age': 'Unknown',
            'contact_info_present': 0,
            'social_media_links': 0,
            'privacy_policy_present': 0,
            'legitimacy_indicators': 50
        }
