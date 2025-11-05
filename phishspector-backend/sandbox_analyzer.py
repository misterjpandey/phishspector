# sandbox_analyzer.py - Synchronous version (no async)
import os
import json
import time
import logging
from datetime import datetime
from urllib.parse import urlparse

# Optional playwright - if not available, sandbox will be disabled
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None

logger = logging.getLogger("sandbox")

class PhishSandbox:
    def __init__(self):
        self.results = {}
        self.screenshots_dir = "screenshots"
        self.reports_dir = "reports"
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Create necessary directories"""
        os.makedirs(self.screenshots_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def analyze_url(self, url, original_email_data=None):
        """Analyze URL in isolated browser environment (SYNC version)"""
        if not PLAYWRIGHT_AVAILABLE:
            return {
                'status': 'failed',
                'error': 'Playwright not available. Install with: pip install playwright && playwright install chromium'
            }
            
        logger.info(f"🔍 Starting sandbox analysis for: {url}")
        
        try:
            with sync_playwright() as p:
                # Launch browser with security settings
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-accelerated-2d-canvas',
                        '--no-first-run',
                        '--no-zygote',
                        '--disable-gpu'
                    ]
                )
                
                # Create isolated context
                context = browser.new_context(
                    viewport={'width': 1280, 'height': 720},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    java_script_enabled=True,
                    ignore_https_errors=True
                )
                
                page = context.new_page()
                
                # Setup event listeners
                network_requests = []
                errors = []
                
                def log_network_request(request):
                    network_requests.append({
                        'url': request.url,
                        'method': request.method,
                        'timestamp': datetime.now().isoformat()
                    })
                
                def log_error(error):
                    errors.append({
                        'error': str(error),
                        'timestamp': datetime.now().isoformat()
                    })
                
                page.on("request", log_network_request)
                page.on("pageerror", log_error)
                
                try:
                    # Navigate to URL with timeout
                    start_time = time.time()
                    response = page.goto(url, wait_until='networkidle', timeout=15000)
                    load_time = time.time() - start_time
                    
                    # Take screenshot
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    screenshot_path = f"{self.screenshots_dir}/screenshot_{timestamp}.png"
                    page.screenshot(path=screenshot_path, full_page=True)
                    
                    # Extract page information
                    page_title = page.title()
                    final_url = page.url
                    page_content = page.content()
                    
                    # Look for phishing indicators
                    phishing_indicators = self._detect_phishing_indicators(page)
                    
                    # Build results
                    self.results = {
                        'analysis_id': f"analysis_{timestamp}",
                        'timestamp': datetime.now().isoformat(),
                        'original_url': url,
                        'final_url': final_url,
                        'page_title': page_title,
                        'load_time_seconds': load_time,
                        'response_status': response.status if response else 'unknown',
                        'screenshot_path': screenshot_path,
                        'phishing_indicators': phishing_indicators,
                        'network_requests_count': len(network_requests),
                        'errors_count': len(errors),
                        'has_redirected': url != final_url,
                        'risk_score': self._calculate_risk_score(phishing_indicators),
                        'email_context': original_email_data,
                        'status': 'success'
                    }
                    
                    logger.info(f"✅ Sandbox analysis completed. Risk: {self.results['risk_score']}%")
                    
                except Exception as e:
                    self.results = {
                        'analysis_id': f"analysis_{timestamp}",
                        'timestamp': datetime.now().isoformat(),
                        'original_url': url,
                        'error': str(e),
                        'status': 'failed'
                    }
                    logger.error(f"❌ Sandbox analysis failed: {e}")
                
                finally:
                    browser.close()
                
                return self.results
                
        except Exception as e:
            logger.error(f"❌ Playwright initialization failed: {e}")
            return {
                'status': 'failed',
                'error': f'Playwright error: {str(e)}'
            }
    
    def _detect_phishing_indicators(self, page):
        """Detect common phishing indicators on the page"""
        indicators = {
            'password_fields': False,
            'login_forms': False,
            'suspicious_keywords': [],
            'iframe_count': 0,
        }
        
        try:
            # Check for password fields
            password_fields = page.query_selector_all('input[type="password"]')
            indicators['password_fields'] = len(password_fields) > 0
            
            # Check for login forms
            login_forms = page.query_selector_all('form')
            indicators['login_forms'] = len(login_forms) > 0
            
            # Check page content for suspicious keywords
            content = page.content()
            suspicious_terms = ['login', 'signin', 'password', 'verify', 'account', 'security', 'banking', 'paypal']
            found_terms = [term for term in suspicious_terms if term.lower() in content.lower()]
            indicators['suspicious_keywords'] = found_terms
            
            # Count iframes
            iframes = page.query_selector_all('iframe')
            indicators['iframe_count'] = len(iframes)
            
        except Exception as e:
            logger.error(f"Error detecting phishing indicators: {e}")
            
        return indicators
    
    def _calculate_risk_score(self, indicators):
        """Calculate risk score based on detected indicators"""
        risk_score = 0
        
        if indicators['password_fields']:
            risk_score += 30
        
        if indicators['login_forms']:
            risk_score += 20
        
        if len(indicators['suspicious_keywords']) >= 3:
            risk_score += 25
        
        if indicators['iframe_count'] > 2:
            risk_score += 15
        
        # Domain-based risk
        domain = urlparse(self.results.get('final_url', '')).netloc
        if self._is_suspicious_domain(domain):
            risk_score += 20
        
        return min(100, risk_score)
    
    def _is_suspicious_domain(self, domain):
        """Check if domain appears suspicious"""
        if not domain:
            return False
            
        suspicious_tlds = ['.xyz', '.top', '.club', '.tk', '.cf', '.ga', '.ml', '.gq']
        suspicious_keywords = ['login', 'verify', 'security', 'account', 'bank', 'paypal']
        
        domain_lower = domain.lower()
        
        # Check TLD
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Check keywords in domain
        if any(keyword in domain_lower for keyword in suspicious_keywords):
            return True
        
        return False
    
    def generate_report(self, analysis_results):
        """Generate comprehensive security report"""
        report_data = {
            'analysis_id': analysis_results.get('analysis_id'),
            'timestamp': analysis_results.get('timestamp'),
            'original_url': analysis_results.get('original_url'),
            'final_url': analysis_results.get('final_url'),
            'risk_score': analysis_results.get('risk_score', 0),
            'risk_level': self._get_risk_level(analysis_results.get('risk_score', 0)),
            'indicators': analysis_results.get('phishing_indicators', {}),
            'technical_details': {
                'load_time': analysis_results.get('load_time_seconds'),
                'response_status': analysis_results.get('response_status'),
                'redirected': analysis_results.get('has_redirected', False),
                'network_requests': analysis_results.get('network_requests_count', 0),
                'errors': analysis_results.get('errors_count', 0)
            },
            'recommendations': self._generate_recommendations(analysis_results)
        }
        
        # Save JSON report
        report_filename = f"{self.reports_dir}/report_{report_data['analysis_id']}.json"
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Generate simple text report
        text_report = self._generate_text_report(report_data)
        text_report_filename = f"{self.reports_dir}/report_{report_data['analysis_id']}.txt"
        with open(text_report_filename, 'w') as f:
            f.write(text_report)
        
        logger.info(f"📄 Report generated: {report_filename}")
        
        return {
            'json_report': report_filename,
            'text_report': text_report_filename,
            'screenshot': analysis_results.get('screenshot_path'),
            'report_data': report_data
        }
    
    def _get_risk_level(self, score):
        if score >= 70:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, results):
        """Generate security recommendations based on findings"""
        recommendations = []
        risk_score = results.get('risk_score', 0)
        
        if risk_score >= 70:
            recommendations.append("🚨 DO NOT INTERACT - This site is highly suspicious")
            recommendations.append("Do not enter any personal information")
            recommendations.append("Do not download any files")
        elif risk_score >= 30:
            recommendations.append("⚠️ Exercise caution - This site shows suspicious characteristics")
            recommendations.append("Verify the website legitimacy before proceeding")
        
        if results.get('phishing_indicators', {}).get('password_fields'):
            recommendations.append("🔒 Site contains password fields - could be credential harvesting")
        
        if results.get('has_redirected'):
            recommendations.append("🔄 Site performed redirects - common phishing tactic")
        
        return recommendations
    
    def _generate_text_report(self, report_data):
        """Generate human-readable text report"""
        report = f"""
PHISHSPECTOR SANDBOX ANALYSIS REPORT
====================================

ANALYSIS SUMMARY:
-----------------
Analysis ID: {report_data['analysis_id']}
Timestamp: {report_data['timestamp']}
Risk Level: {report_data['risk_level']} ({report_data['risk_score']}%)

URL INFORMATION:
----------------
Original URL: {report_data['original_url']}
Final URL: {report_data['final_url']}

SECURITY FINDINGS:
------------------
Risk Score: {report_data['risk_score']}% ({report_data['risk_level']})

Phishing Indicators Detected:
• Password Fields: {report_data['indicators'].get('password_fields', False)}
• Login Forms: {report_data['indicators'].get('login_forms', False)}
• Suspicious Keywords: {', '.join(report_data['indicators'].get('suspicious_keywords', []))}
• Iframe Count: {report_data['indicators'].get('iframe_count', 0)}

Technical Details:
• Page Load Time: {report_data['technical_details']['load_time']:.2f} seconds
• HTTP Status: {report_data['technical_details']['response_status']}
• Was Redirected: {report_data['technical_details']['redirected']}
• Network Requests: {report_data['technical_details']['network_requests']}
• Errors Encountered: {report_data['technical_details']['errors']}

SECURITY RECOMMENDATIONS:
-------------------------
{chr(10).join(f"• {rec}" for rec in report_data['recommendations'])}

---
Report generated by PhishSpector Sandbox
        """
        return report

# Singleton instance
sandbox = PhishSandbox()