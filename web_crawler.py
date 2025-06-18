import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import logging
import re
import ssl
import socket
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import whois
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)

class WebCrawler:
    def __init__(self):
        """Initialize the web crawler with session and configurations"""
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers to mimic a real browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Timeout configurations
        self.timeout = 10
        self.max_content_length = 1024 * 1024  # 1MB
        
        # Patterns for extracting specific information
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.phone_pattern = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
        self.social_media_patterns = {
            'facebook': re.compile(r'facebook\.com/[A-Za-z0-9._-]+', re.IGNORECASE),
            'twitter': re.compile(r'twitter\.com/[A-Za-z0-9._-]+', re.IGNORECASE),
            'instagram': re.compile(r'instagram\.com/[A-Za-z0-9._-]+', re.IGNORECASE),
            'linkedin': re.compile(r'linkedin\.com/[A-Za-z0-9._-]+', re.IGNORECASE)
        }
    
    def crawl_url(self, url):
        """Crawl a single URL and extract relevant content"""
        try:
            # Validate URL
            if not self._is_valid_url(url):
                return {
                    'success': False,
                    'error': 'Invalid URL format'
                }
            
            logger.info(f"Crawling URL: {url}")
            
            # Make HTTP request
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True
            )
            
            # Check content length
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.max_content_length:
                response.close()
                return {
                    'success': False,
                    'error': 'Content too large'
                }
            
            # Check response status
            response.raise_for_status()
            
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract content and metadata
            content = self._extract_content(soup)
            metadata = self._extract_metadata(soup, response, url)
            
            return {
                'success': True,
                'content': content,
                'metadata': metadata,
                'status_code': response.status_code
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error'
            }
        except requests.exceptions.HTTPError as e:
            return {
                'success': False,
                'error': f'HTTP error: {e.response.status_code}'
            }
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            return {
                'success': False,
                'error': f'Crawling error: {str(e)}'
            }
    
    def _is_valid_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _extract_content(self, soup):
        """Extract main content from HTML"""
        try:
            # Remove script and style elements
            for element in soup(["script", "style", "nav", "footer", "aside"]):
                element.decompose()
            
            # Try to find main content areas
            main_content = ""
            
            # Look for common content containers
            content_selectors = [
                'main', 'article', '.content', '#content',
                '.main-content', '.post-content', '.entry-content',
                '.scholarship-details', '.description', '.body-content',
                '.page-content', '.text-content'
            ]
            
            for selector in content_selectors:
                elements = soup.select(selector)
                if elements:
                    main_content = " ".join([elem.get_text(strip=True) for elem in elements])
                    break
            
            # If no specific content area found, extract from body
            if not main_content:
                body = soup.find('body')
                if body:
                    main_content = body.get_text(strip=True)
                else:
                    main_content = soup.get_text(strip=True)
            
            # Clean up the content
            main_content = self._clean_content(main_content)
            
            return main_content
            
        except Exception as e:
            logger.error(f"Error extracting content: {str(e)}")
            return ""
    
    def _extract_metadata(self, soup, response, url):
        """Extract metadata from HTML and response"""
        try:
            metadata = {
                'url': url,
                'title': '',
                'description': '',
                'keywords': [],
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'server': response.headers.get('server', ''),
                'last_modified': response.headers.get('last-modified', ''),
                'ssl_certificate': self._check_ssl_certificate(url),
                'domain_info': self._get_domain_info(url),
                'social_media_links': self._extract_social_media_links(soup),
                'contact_info': self._extract_contact_info(soup),
                'forms': self._analyze_forms(soup),
                'external_links': self._count_external_links(soup, url),
                'images': self._count_images(soup),
                'javascript_includes': self._count_javascript(soup),
                'privacy_policy_present': self._check_privacy_policy(soup),
                'terms_of_service_present': self._check_terms_of_service(soup)
            }
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.get_text(strip=True)
            
            # Extract meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                metadata['description'] = meta_desc.get('content', '')
            
            # Extract meta keywords
            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            if meta_keywords:
                keywords_content = meta_keywords.get('content', '')
                metadata['keywords'] = [k.strip() for k in keywords_content.split(',')]
            
            # Extract Open Graph data
            og_title = soup.find('meta', property='og:title')
            og_description = soup.find('meta', property='og:description')
            if og_title and not metadata['title']:
                metadata['title'] = og_title.get('content', '')
            if og_description and not metadata['description']:
                metadata['description'] = og_description.get('content', '')
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting metadata: {str(e)}")
            return {
                'url': url,
                'title': '',
                'description': '',
                'keywords': [],
                'content_length': 0,
                'ssl_certificate': False,
                'domain_info': {},
                'social_media_links': [],
                'contact_info': {},
                'forms': [],
                'external_links': 0,
                'images': 0,
                'javascript_includes': 0,
                'privacy_policy_present': False,
                'terms_of_service_present': False
            }
    
    def _clean_content(self, content):
        """Clean and normalize extracted content"""
        if not content:
            return ""
        
        # Remove extra whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove special characters that might interfere with analysis
        content = re.sub(r'[^\w\s\.\!\?\,\;\:\-\(\)\[\]\{\}\"\'\/\\@#$%&*+=<>]', '', content)
        
        # Remove extremely long strings (might be encoded data)
        words = content.split()
        filtered_words = [word for word in words if len(word) < 50]
        content = ' '.join(filtered_words)
        
        return content.strip()
    
    def _check_ssl_certificate(self, url):
        """Check if URL has valid SSL certificate"""
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return False
            
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If we get here, SSL certificate is valid
                    return True
                    
        except Exception as e:
            logger.debug(f"SSL check failed for {url}: {str(e)}")
            return False
    
    def _get_domain_info(self, url):
        """Get domain registration information"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Get WHOIS information
            domain_info = whois.whois(domain)
            
            result = {
                'domain': domain,
                'registrar': getattr(domain_info, 'registrar', 'Unknown'),
                'creation_date': None,
                'expiration_date': None,
                'age_days': 0,
                'nameservers': getattr(domain_info, 'name_servers', [])
            }
            
            # Parse creation date
            creation_date = getattr(domain_info, 'creation_date', None)
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, str):
                    try:
                        creation_date = date_parser.parse(creation_date)
                    except:
                        creation_date = None
                
                if creation_date:
                    result['creation_date'] = creation_date.isoformat()
                    age_delta = datetime.now() - creation_date
                    result['age_days'] = age_delta.days
            
            # Parse expiration date
            expiration_date = getattr(domain_info, 'expiration_date', None)
            if expiration_date:
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if isinstance(expiration_date, str):
                    try:
                        expiration_date = date_parser.parse(expiration_date)
                    except:
                        expiration_date = None
                
                if expiration_date:
                    result['expiration_date'] = expiration_date.isoformat()
            
            return result
            
        except Exception as e:
            logger.debug(f"Domain info lookup failed for {url}: {str(e)}")
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return {
                'domain': domain,
                'registrar': 'Unknown',
                'creation_date': None,
                'expiration_date': None,
                'age_days': 0,
                'nameservers': []
            }
    
    def _extract_social_media_links(self, soup):
        """Extract social media links from the page"""
        social_links = []
        
        # Find all links
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href'].lower()
            for platform, pattern in self.social_media_patterns.items():
                if pattern.search(href):
                    social_links.append({
                        'platform': platform,
                        'url': href
                    })
                    break
        
        return social_links
    
    def _extract_contact_info(self, soup):
        """Extract contact information from the page"""
        page_text = soup.get_text()
        
        # Find email addresses
        emails = self.email_pattern.findall(page_text)
        
        # Find phone numbers
        phones = self.phone_pattern.findall(page_text)
        
        # Look for address patterns (basic implementation)
        address_keywords = ['address', 'location', 'office', 'headquarters']
        potential_addresses = []
        
        for keyword in address_keywords:
            pattern = re.compile(rf'{keyword}[:\s]*(.{{0,200}})', re.IGNORECASE)
            matches = pattern.findall(page_text)
            potential_addresses.extend(matches)
        
        return {
            'emails': list(set(emails)),  # Remove duplicates
            'phones': list(set(phones)),
            'addresses': potential_addresses[:5]  # Limit to first 5
        }
    
    def _analyze_forms(self, soup):
        """Analyze forms on the page"""
        forms = soup.find_all('form')
        form_info = []
        
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': [],
                'has_file_upload': False,
                'has_payment_fields': False
            }
            
            # Analyze input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_field in inputs:
                input_info = {
                    'type': input_field.get('type', 'text'),
                    'name': input_field.get('name', ''),
                    'required': input_field.has_attr('required'),
                    'placeholder': input_field.get('placeholder', '')
                }
                form_data['inputs'].append(input_info)
                
                # Check for file upload
                if input_info['type'] == 'file':
                    form_data['has_file_upload'] = True
                
                # Check for payment-related fields
                payment_keywords = ['payment', 'credit', 'card', 'billing', 'amount', 'fee']
                field_text = (input_info['name'] + input_info['placeholder']).lower()
                if any(keyword in field_text for keyword in payment_keywords):
                    form_data['has_payment_fields'] = True
            
            form_info.append(form_data)
        
        return form_info
    
    def _count_external_links(self, soup, current_url):
        """Count external links on the page"""
        current_domain = urlparse(current_url).netloc.lower()
        if current_domain.startswith('www.'):
            current_domain = current_domain[4:]
        
        external_count = 0
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            if href.startswith('http'):
                link_domain = urlparse(href).netloc.lower()
                if link_domain.startswith('www.'):
                    link_domain = link_domain[4:]
                
                if link_domain != current_domain:
                    external_count += 1
        
        return external_count
    
    def _count_images(self, soup):
        """Count images on the page"""
        return len(soup.find_all('img'))
    
    def _count_javascript(self, soup):
        """Count JavaScript includes and inline scripts"""
        external_js = len(soup.find_all('script', src=True))
        inline_js = len(soup.find_all('script', src=False))
        return external_js + inline_js
    
    def _check_privacy_policy(self, soup):
        """Check if privacy policy link is present"""
        privacy_keywords = ['privacy policy', 'privacy', 'data protection']
        
        # Check in links
        links = soup.find_all('a', href=True)
        for link in links:
            link_text = link.get_text().lower()
            if any(keyword in link_text for keyword in privacy_keywords):
                return True
        
        # Check in page text
        page_text = soup.get_text().lower()
        return any(keyword in page_text for keyword in privacy_keywords)
    
    def _check_terms_of_service(self, soup):
        """Check if terms of service link is present"""
        terms_keywords = ['terms of service', 'terms', 'terms and conditions', 'user agreement']
        
        # Check in links
        links = soup.find_all('a', href=True)
        for link in links:
            link_text = link.get_text().lower()
            if any(keyword in link_text for keyword in terms_keywords):
                return True
        
        # Check in page text
        page_text = soup.get_text().lower()
        return any(keyword in page_text for keyword in terms_keywords)
    
    def crawl_multiple_urls(self, urls, delay=1):
        """Crawl multiple URLs with optional delay between requests"""
        results = []
        
        for i, url in enumerate(urls):
            if i > 0 and delay > 0:
                time.sleep(delay)
            
            result = self.crawl_url(url)
            results.append(result)
            
            logger.info(f"Crawled {i+1}/{len(urls)}: {url}")
        
        return results
    
    def get_page_structure_info(self, soup):
        """Analyze the structure of the HTML page"""
        try:
            return {
                'total_elements': len(soup.find_all()),
                'div_count': len(soup.find_all('div')),
                'paragraph_count': len(soup.find_all('p')),
                'heading_count': len(soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])),
                'list_count': len(soup.find_all(['ul', 'ol'])),
                'table_count': len(soup.find_all('table')),
                'form_count': len(soup.find_all('form')),
                'iframe_count': len(soup.find_all('iframe')),
                'video_count': len(soup.find_all(['video', 'embed', 'object'])),
            }
        except Exception as e:
            logger.error(f"Error analyzing page structure: {str(e)}")
            return {}
    
    def close_session(self):
        """Close the requests session"""
        self.session.close()