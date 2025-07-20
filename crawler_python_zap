"""
OWASP ZAP Advanced Crawler Plugin
Based on Katana-like Python crawler adapted for ZAP integration
Type: Targeted Technology Script or Stand Alone Script
"""

import re
import json
import time
from urllib.parse import urlparse, urljoin, urlunparse
from collections import deque
from java.net import URL
from org.apache.commons.httpclient import URI
from org.parosproxy.paros.network import HttpMessage, HttpRequestHeader
from org.parosproxy.paros.core.scanner import Plugin
from org.zaproxy.zap.extension.script import ScriptVars

# ZAP Helper functions
def getHttpSender():
    """Get HTTP sender from ZAP"""
    from org.parosproxy.paros.network import HttpSender
    return HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)

def sendRequest(msg):
    """Send HTTP request through ZAP"""
    sender = getHttpSender()
    sender.sendAndReceive(msg)
    return msg

class ZAPCrawler:
    """Advanced crawler for ZAP integration"""
    
    def __init__(self, zap_helper=None):
        self.helper = zap_helper
        self.visited_urls = set()
        self.queued_urls = set()
        self.queue = deque()
        self.results = []
        self.max_depth = 3
        self.scope_patterns = []
        self.out_scope_patterns = []
        self.extract_forms = True
        self.extract_emails = True
        self.extract_comments = True
        self.follow_redirects = True
        self.max_crawl_size = 1000  # Maximum URLs to crawl
        
    def log(self, message):
        """Log message to ZAP console"""
        if self.helper:
            self.helper.writeOutput(message + "\n")
        else:
            print(message)
    
    def normalize_url(self, url):
        """Normalize URL for consistency"""
        try:
            parsed = urlparse(url.lower())
            # Remove fragment
            normalized = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, '')
            )
            # Remove trailing slash for consistency
            if normalized.endswith('/') and normalized.count('/') > 3:
                normalized = normalized[:-1]
            return normalized
        except:
            return url
    
    def is_in_scope(self, url):
        """Check if URL is in scope"""
        # Check out of scope first
        for pattern in self.out_scope_patterns:
            if re.search(pattern, url):
                return False
        
        # If no scope patterns defined, everything is in scope
        if not self.scope_patterns:
            return True
        
        # Check if URL matches any scope pattern
        for pattern in self.scope_patterns:
            if re.search(pattern, url):
                return True
        
        return False
    
    def extract_links_from_html(self, html, base_url):
        """Extract links from HTML content"""
        links = set()
        
        # Extract href links
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            link = match.group(1)
            absolute_link = urljoin(base_url, link)
            links.add(absolute_link)
        
        # Extract src links
        src_pattern = r'src\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            link = match.group(1)
            absolute_link = urljoin(base_url, link)
            links.add(absolute_link)
        
        # Extract form actions
        action_pattern = r'action\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(action_pattern, html, re.IGNORECASE):
            link = match.group(1)
            absolute_link = urljoin(base_url, link)
            links.add(absolute_link)
        
        # Extract JavaScript links
        js_patterns = [
            r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'["\']([^"\']*?\.(?:html?|php|asp|jsp|do|action))["\']',
            r'(?:href|src|url)\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in js_patterns:
            for match in re.finditer(pattern, html):
                link = match.group(1)
                if link.startswith(('http', '/', './')):
                    absolute_link = urljoin(base_url, link)
                    links.add(absolute_link)
        
        return list(links)
    
    def extract_forms_from_html(self, html, base_url):
        """Extract forms from HTML"""
        forms = []
        
        # Simple form extraction using regex
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            form_data = {
                'html': form_html,
                'action': '',
                'method': 'GET',
                'inputs': []
            }
            
            # Extract action
            action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_data['action'] = urljoin(base_url, action_match.group(1))
            else:
                form_data['action'] = base_url
            
            # Extract method
            method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if method_match:
                form_data['method'] = method_match.group(1).upper()
            
            # Extract inputs
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                input_data = {
                    'name': '',
                    'type': 'text',
                    'value': ''
                }
                
                # Extract name
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                if name_match:
                    input_data['name'] = name_match.group(1)
                
                # Extract type
                type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                if type_match:
                    input_data['type'] = type_match.group(1)
                
                # Extract value
                value_match = re.search(r'value\s*=\s*["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                if value_match:
                    input_data['value'] = value_match.group(1)
                
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_emails_from_html(self, html):
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, html)))
    
    def extract_comments_from_html(self, html):
        """Extract HTML comments"""
        comment_pattern = r'<!--(.*?)-->'
        return [c.strip() for c in re.findall(comment_pattern, html, re.DOTALL)]
    
    def detect_technologies(self, html, headers):
        """Detect technologies used"""
        technologies = []
        
        tech_signatures = {
            'WordPress': [r'wp-content', r'wp-includes'],
            'Drupal': [r'sites/all', r'sites/default'],
            'Joomla': [r'option=com_', r'joomla'],
            'React': [r'react\.production\.min\.js', r'_react'],
            'Angular': [r'angular\.min\.js', r'ng-app'],
            'Vue.js': [r'vue\.min\.js', r'v-if'],
            'jQuery': [r'jquery\.min\.js', r'jQuery'],
            'Bootstrap': [r'bootstrap\.min\.css', r'bootstrap\.min\.js'],
            'Laravel': [r'laravel_session'],
            'Django': [r'csrfmiddlewaretoken'],
            'ASP.NET': [r'__VIEWSTATE', r'aspnet']
        }
        
        # Check HTML content
        for tech, patterns in tech_signatures.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        # Check headers
        if headers:
            server = headers.get('Server', '').lower()
            powered_by = headers.get('X-Powered-By', '').lower()
            
            if 'nginx' in server:
                technologies.append('Nginx')
            if 'apache' in server:
                technologies.append('Apache')
            if 'iis' in server:
                technologies.append('IIS')
            if 'php' in powered_by:
                technologies.append('PHP')
            if 'asp' in powered_by:
                technologies.append('ASP.NET')
        
        return list(set(technologies))
    
    def crawl_url(self, url):
        """Crawl a single URL using ZAP"""
        try:
            normalized_url = self.normalize_url(url)
            
            # Check if already visited
            if normalized_url in self.visited_urls:
                return None
            
            self.visited_urls.add(normalized_url)
            
            # Check scope
            if not self.is_in_scope(url):
                self.log(f"URL out of scope: {url}")
                return None
            
            self.log(f"Crawling: {url}")
            
            # Create HTTP message
            msg = HttpMessage()
            uri = URI(url, True)
            msg.setRequestHeader(HttpRequestHeader(HttpRequestHeader.GET, uri, HttpRequestHeader.HTTP11))
            
            # Send request through ZAP
            start_time = time.time()
            sendRequest(msg)
            response_time = time.time() - start_time
            
            # Get response
            response_header = msg.getResponseHeader()
            response_body = msg.getResponseBody().toString()
            
            # Parse response
            result = {
                'url': url,
                'status_code': response_header.getStatusCode(),
                'content_length': len(response_body),
                'content_type': response_header.getHeader('Content-Type') or '',
                'response_time': response_time,
                'technologies': [],
                'forms': [],
                'links': [],
                'emails': [],
                'comments': [],
                'headers': {}
            }
            
            # Extract headers
            for header in response_header.getHeaders():
                name = header.getName()
                value = header.getValue()
                result['headers'][name] = value
            
            # Only parse HTML responses
            if 'text/html' in result['content_type']:
                # Extract links
                result['links'] = self.extract_links_from_html(response_body, url)
                
                # Extract forms
                if self.extract_forms:
                    result['forms'] = self.extract_forms_from_html(response_body, url)
                
                # Extract emails
                if self.extract_emails:
                    result['emails'] = self.extract_emails_from_html(response_body)
                
                # Extract comments
                if self.extract_comments:
                    result['comments'] = self.extract_comments_from_html(response_body)
                
                # Detect technologies
                result['technologies'] = self.detect_technologies(response_body, result['headers'])
                
                # Add discovered links to queue
                for link in result['links']:
                    normalized_link = self.normalize_url(link)
                    if normalized_link not in self.visited_urls and normalized_link not in self.queued_urls:
                        if self.is_in_scope(link):
                            self.queued_urls.add(normalized_link)
                            self.queue.append(link)
            
            return result
            
        except Exception as e:
            self.log(f"Error crawling {url}: {str(e)}")
            return None
    
    def crawl(self, start_urls, max_depth=3, scope_regex=None):
        """Main crawl method"""
        self.max_depth = max_depth
        if scope_regex:
            self.scope_patterns = [scope_regex]
        
        # Add start URLs to queue
        for url in start_urls:
            self.queued_urls.add(self.normalize_url(url))
            self.queue.append(url)
        
        # Crawl URLs
        while self.queue and len(self.visited_urls) < self.max_crawl_size:
            url = self.queue.popleft()
            result = self.crawl_url(url)
            
            if result:
                self.results.append(result)
                
                # Log progress
                self.log(f"Crawled: {result['url']} [{result['status_code']}] - Found {len(result['links'])} links, {len(result['forms'])} forms")
                
                # Report to ZAP
                if result['forms']:
                    self.log(f"Forms found at {url}:")
                    for form in result['forms']:
                        self.log(f"  - {form['method']} {form['action']}")
                
                if result['technologies']:
                    self.log(f"Technologies detected: {', '.join(result['technologies'])}")
        
        self.log(f"\nCrawl complete. Visited {len(self.visited_urls)} URLs")
        return self.results

# ZAP Script Interface Functions

def scan(ps, msg, src):
    """
    ZAP Active Scanner Plugin Interface
    This is called by ZAP for active scanning
    """
    # Initialize crawler
    crawler = ZAPCrawler()
    crawler.log("Starting advanced crawl scan...")
    
    # Get base URL
    base_url = msg.getRequestHeader().getURI().toString()
    
    # Perform crawl
    results = crawler.crawl([base_url], max_depth=3)
    
    # Report findings to ZAP
    for result in results:
        # Report forms
        for form in result.get('forms', []):
            ps.raiseAlert(
                Plugin.RISK_INFO,
                Plugin.CONFIDENCE_MEDIUM,
                "Form Discovered",
                f"Form found: {form['method']} {form['action']}",
                result['url'],
                "",
                "",
                json.dumps(form),
                "",
                msg
            )
        
        # Report technologies
        if result.get('technologies'):
            ps.raiseAlert(
                Plugin.RISK_INFO,
                Plugin.CONFIDENCE_HIGH,
                "Technologies Detected",
                f"Technologies: {', '.join(result['technologies'])}",
                result['url'],
                "",
                "",
                json.dumps(result['technologies']),
                "",
                msg
            )
        
        # Report emails
        if result.get('emails'):
            ps.raiseAlert(
                Plugin.RISK_INFO,
                Plugin.CONFIDENCE_HIGH,
                "Email Addresses Found",
                f"Emails: {', '.join(result['emails'])}",
                result['url'],
                "",
                "",
                json.dumps(result['emails']),
                "",
                msg
            )

def standalone():
    """
    Standalone script execution
    Can be run from ZAP Scripts tab
    """
    print("Advanced Crawler - Standalone Mode")
    print("==================================")
    
    # Get target URL from user
    target_url = raw_input("Enter target URL: ")
    
    # Initialize crawler
    crawler = ZAPCrawler()
    
    # Configure crawler
    max_depth = int(raw_input("Max depth (default 3): ") or "3")
    scope_pattern = raw_input("Scope regex (optional): ")
    
    # Perform crawl
    results = crawler.crawl([target_url], max_depth, scope_pattern)
    
    # Output results
    print(f"\nCrawl Results ({len(results)} URLs found):")
    print("=" * 50)
    
    for result in results:
        print(f"\nURL: {result['url']}")
        print(f"Status: {result['status_code']}")
        print(f"Technologies: {', '.join(result['technologies'])}")
        print(f"Forms: {len(result['forms'])}")
        print(f"Links: {len(result['links'])}")
        print(f"Emails: {len(result['emails'])}")
        
        if result['forms']:
            print("Forms:")
            for form in result['forms']:
                print(f"  - {form['method']} {form['action']}")
    
    # Save results
    save_results = raw_input("\nSave results to file? (y/n): ")
    if save_results.lower() == 'y':
        filename = raw_input("Filename (default: crawl_results.json): ") or "crawl_results.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {filename}")

def targeted(ps, msg, param, value):
    """
    ZAP Targeted Scanner Plugin Interface
    This is called for specific parameter testing
    """
    # For targeted scanning, we can check if the parameter appears in forms
    crawler = ZAPCrawler()
    base_url = msg.getRequestHeader().getURI().toString()
    
    # Quick crawl to find forms
    results = crawler.crawl([base_url], max_depth=1)
    
    for result in results:
        for form in result.get('forms', []):
            for input_field in form.get('inputs', []):
                if input_field.get('name') == param:
                    ps.raiseAlert(
                        Plugin.RISK_INFO,
                        Plugin.CONFIDENCE_MEDIUM,
                        f"Parameter '{param}' found in form",
                        f"The parameter '{param}' was found in a form at {form['action']}",
                        result['url'],
                        param,
                        "",
                        json.dumps(form),
                        "",
                        msg
                    )

# If running as standalone script
if __name__ == "__main__":
    standalone()
