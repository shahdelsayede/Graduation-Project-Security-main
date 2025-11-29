from flask import Flask, render_template, request, url_for, redirect
import requests
from bs4 import BeautifulSoup
import difflib
import asyncio
import aiohttp
import time
import uuid
import concurrent.futures
import urllib.parse
import json
import re

# Initialize the Flask application
app = Flask(__name__)

# ==========================================
#  VULNERABILITY DATA DICTIONARY
# ==========================================
vulnerabilities = {
    'csrf_scanner': {
        'name': 'CSRF Form Scanner',
        'description': 'A passive scanner that checks forms on a public webpage for CSRF protection tokens.'
    },
    'idor_scanner': {
        'name': 'IDOR Scanner',
        'description': 'Tests for Insecure Direct Object References by iterating IDs in a URL template.'
    },
    'sqli_scanner': {
        'name': 'SQL Injection Scanner',
        'description': 'Tests URL parameters for SQL Injection using boolean, error, and time-based payloads.'
    },
    'xss_advanced': {
        'name': 'Advanced XSS Scanner',
        'description': 'Active scanner using polyglots and token tracing to detect Reflected XSS in parameters and forms.'
    },
    'subdomain_scanner': {
        'name': 'Passive Subdomain Enumerator',
        'description': 'Uses public Certificate Transparency logs (crt.sh) to find subdomains, then validates if they are active.'
    }
}

# ==========================================
# 1. CSRF SCANNER LOGIC
# ==========================================

COMMON_CSRF_NAMES = ['csrf', 'csrf_token', '_csrf', 'token', '__RequestVerificationToken', 'authenticity_token', 'xsrf', 'anti_csrf']

def get_forms(url, timeout=10):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        forms_data = []
        for f in soup.find_all('form'):
            action = f.get('action') or url
            method = (f.get('method') or 'get').lower()
            inputs = {inp.get('name'): inp.get('type') for inp in f.find_all('input') if inp.get('name')}
            forms_data.append({'action': action, 'method': method, 'inputs': inputs})
        return forms_data, r.headers
    except:
        return [], {}

def has_csrf_token(inputs):
    for name in inputs:
        if name:
            lname = name.lower()
            for token_name in COMMON_CSRF_NAMES:
                if token_name in lname: return True, name
    return False, None


# ==========================================
# 2. IDOR SCANNER LOGIC
# ==========================================

def scan_idor(url_template, start=1, end=20, timeout=10):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    baseline = None
    results = []
    for i in range(start, end+1):
        url = url_template.format(id=i)
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            status = r.status_code
            length = len(r.text)
            text = r.text[:2000]
        except Exception as e:
            results.append({'id': i, 'url': url, 'error': str(e)})
            continue
        if baseline is None:
            baseline = {'status': status, 'length': length, 'text': text, 'id': i}
            results.append({'id': i, 'url': url, 'status': status, 'length': length, 'info': 'baseline'})
            continue
        sim = difflib.SequenceMatcher(None, baseline['text'], text).ratio()
        differing = (status != baseline['status']) or (length != baseline['length']) or sim < 0.95
        results.append({'id': i, 'url': url, 'status': status, 'length': length, 'similarity_with_baseline': round(sim, 3), 'potential_idor': differing})
    return results


# ==========================================
# 3. SQL INJECTION SCANNER LOGIC
# ==========================================

SAFE_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1 OR 1=1", "1' AND SLEEP(2)--", "1\" AND SLEEP(2)--"]

class SQLiScanner:
    def __init__(self, url, timeout=7):
        self.url = url
        self.timeout = timeout
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    async def fetch(self, session, url):
        start_time = time.time()
        try:
            async with session.get(url, headers=self.headers, timeout=self.timeout) as r:
                text = await r.text()
                return {"status": r.status, "text": text, "time": time.time() - start_time}
        except: return None

    async def scan(self):
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        report = []
        if not params: return [{"type": "INFO", "parameter": "N/A", "payload": "N/A", "evidence": "No URL parameters found."}]
        
        async with aiohttp.ClientSession() as session:
            baseline = await self.fetch(session, self.url)
            if not baseline: return [{"type": "ERROR", "parameter": "N/A", "payload": "N/A", "evidence": "Baseline fetch failed."}]
            
            for key in params:
                for payload in SAFE_PAYLOADS:
                    new = params.copy()
                    new[key] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new, doseq=True)}"
                    result = await self.fetch(session, test_url)
                    
                    if not result: continue
                    
                    diff_ratio = abs(len(result["text"]) - len(baseline["text"])) / (len(baseline["text"]) + 1)
                    if diff_ratio > 0.10: 
                        report.append({"parameter": key, "payload": payload, "type": "BOOLEAN / ERROR", "evidence": f"Len changed ({len(baseline['text'])} vs {len(result['text'])})"})
                    
                    if result["status"] != baseline["status"]: 
                        report.append({"parameter": key, "payload": payload, "type": "HTTP CODE CHANGE", "evidence": f"Status {baseline['status']} -> {result['status']}"})
                    
                    if "SLEEP" in payload and (result["time"] - baseline["time"] > 1.5): 
                        report.append({"parameter": key, "payload": payload, "type": "TIME-BASED", "evidence": f"Delay {round(result['time'], 2)}s"})
        return report


# ==========================================
# 4. ADVANCED XSS LOGIC
# ==========================================

XSS_POLYGLOTS = [
    "<script>/{t}/alert(1)</script>",
    "'\"><img src=x onerror=/{t}/alert(1)>",
    "<svg/onload=/{t}/alert(1)>",
    "\"><script>/{t}/</script>",
    "<iframe srcdoc=<'><svg/onload=/{t}/alert(1)>></iframe>",
    "';/{t}/alert(1);//",
    "\"><div style=background-image:url(javascript:/{t}/alert(1))></div>",
    "<math><mi xmlns=javascript:/{t}/alert(1)></mi></math>"
]

def gen_token():
    return 'xsstk_' + uuid.uuid4().hex[:10]

def discover_parameters(url, html_text=None):
    params = set()
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)
    for p in q.keys():
        params.add(p)
    if html_text:
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            for f in soup.find_all('form'):
                for inp in f.find_all(['input','textarea','select']):
                    name = inp.get('name')
                    if name: params.add(name)
        except: pass
    return params

def inject_payloads_to_params(base_url, params_list, payload, method='GET'):
    parsed = urllib.parse.urlparse(base_url)
    base_q = urllib.parse.parse_qs(parsed.query)
    targets = []
    for p in params_list:
        qcopy = {k: v[:] for k,v in base_q.items()}
        qcopy[p] = [payload]
        query = urllib.parse.urlencode({k: v[0] for k,v in qcopy.items()}, doseq=False)
        url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
        if method.upper() == 'GET':
            targets.append(('GET', url, None))
        else:
            targets.append(('POST', base_url, {p: payload}))
    return targets

def analyze_response_for_token(resp_text, token):
    r = {'raw': False, 'in_script': False, 'in_attribute': False, 'snippet': None}
    if token in resp_text:
        r['raw'] = True
        if re.search(re.compile(r'<script[^>]>.' + re.escape(token) + r'.*</script>', re.IGNORECASE|re.DOTALL), resp_text):
            r['in_script'] = True
        if re.search(re.compile(r'=[\"\'][^\"\']' + re.escape(token) + r'[^\"\'][\"\']', re.IGNORECASE), resp_text):
            r['in_attribute'] = True
        idx = resp_text.find(token)
        start = max(0, idx-80)
        end = min(len(resp_text), idx+80)
        r['snippet'] = resp_text[start:end].replace('\n',' ')
    return r

def test_single_target(session, task):
    method = task['method']
    url = task['url']
    data = task.get('data')
    headers = task.get('headers', {'User-Agent': 'Mozilla/5.0'})
    timeout = task.get('timeout', 10)
    try:
        if method == 'GET':
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        else:
            resp = session.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=True)
        text = resp.text or ''
        analysis = analyze_response_for_token(text, task['token'])
        return {
            'method': method, 'url': url, 'payload': task['payload'],
            'status': resp.status_code, 'length': len(text),
            'analysis': analysis, 'csp': resp.headers.get('content-security-policy')
        }
    except Exception as e:
        return {'method': method, 'url': url, 'error': str(e), 'payload': task['payload']}

def build_tasks_for_scan(base_url, discovered_params, test_methods, token, timeout=10):
    tasks = []
    for m in test_methods:
        targets = inject_payloads_to_params(base_url, discovered_params, None, method=m)
        for _, url, data in targets:
            for poly in XSS_POLYGLOTS:
                payload = poly.replace('{t}', token)
                tdict = {
                    'method': m,
                    'url': url if m == 'GET' else url,
                    'data': None if m=='GET' else {list(data.keys())[0]: payload} if data else None,
                    'payload': payload, 'token': token,
                    'headers': {'User-Agent': 'Mozilla/5.0'}, 'timeout': timeout
                }
                if m == 'GET':
                    parsed = urllib.parse.urlparse(url)
                    q = urllib.parse.parse_qs(parsed.query)
                    for k in q.keys(): q[k] = [payload]
                    new_query = urllib.parse.urlencode({k:v[0] for k,v in q.items()}, doseq=False)
                    tdict['url'] = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                tasks.append(tdict)
    return tasks

def run_advanced_xss_scan(base_url, param_list=None, test_methods=['GET'], timeout=10, max_workers=10, crawl=False, max_forms=10):
    session = requests.Session()
    initial_html = None
    try:
        r0 = session.get(base_url, headers={'User-Agent':'Mozilla/5.0'}, timeout=timeout)
        initial_html = r0.text
    except: pass

    discovered = set(param_list or [])
    if not param_list:
        discovered |= discover_parameters(base_url, initial_html)

    form_targets = []
    if crawl and initial_html:
        try:
            soup = BeautifulSoup(initial_html, 'html.parser')
            forms = soup.find_all('form')[:max_forms]
            for f in forms:
                action = f.get('action') or base_url
                method = (f.get('method') or 'get').upper()
                inputs = [inp.get('name') for inp in f.find_all(['input','textarea','select']) if inp.get('name')]
                if inputs:
                    form_targets.append({'action': urllib.parse.urljoin(base_url, action), 'method': method, 'inputs': inputs})
        except: pass

    token = gen_token()
    if not discovered: discovered = {'q'}
    tasks = build_tasks_for_scan(base_url, list(discovered), test_methods, token, timeout=timeout)

    for ft in form_targets:
        for poly in XSS_POLYGLOTS:
            payload = poly.replace('{t}', token)
            if ft['method'] == 'GET':
                parsed = urllib.parse.urlparse(ft['action'])
                q = urllib.parse.parse_qs(parsed.query)
                if ft['inputs']: q[ft['inputs'][0]] = [payload]
                newq = urllib.parse.urlencode({k:v[0] for k,v in q.items()}, doseq=False)
                url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, newq, parsed.fragment))
                tasks.append({'method':'GET','url':url,'data':None,'payload':payload,'token':token,'headers':{'User-Agent':'Mozilla/5.0'},'timeout':timeout})
            else:
                data = {ft['inputs'][0]: payload}
                tasks.append({'method':'POST','url':ft['action'],'data':data,'payload':payload,'token':token,'headers':{'User-Agent':'Mozilla/5.0'},'timeout':timeout})

    results = []
    max_workers = min(max_workers, len(tasks) or 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(test_single_target, session, t) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            try: results.append(f.result())
            except Exception as e: results.append({'error': str(e)})

    hits = [r for r in results if isinstance(r, dict) and r.get('analysis') and r['analysis'].get('raw')]
    return {'base_url': base_url, 'token': token, 'discovered_params': sorted(list(discovered)), 'total_tests': len(results), 'hits': hits, 'all_results': results}


# ==========================================
# 5. SUBDOMAIN SCANNER LOGIC (IMPROVED HYBRID)
# ==========================================

def scan_subdomains_passive(domain):
    """
    Queries crt.sh to find subdomains. Returns a set of strings.
    """
    # Using crt.sh
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    subdomains = set()
    
    try:
        # Increased timeout for large domains
        response = requests.get(url, headers=headers, timeout=60)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry['name_value']
                for sub in name_value.split('\n'):
                    if not '*' in sub: 
                        subdomains.add(sub.lower())
    except Exception as e:
        return {'error': str(e)}

    return sorted(list(subdomains))

async def check_domain_status(session, subdomain):
    """
    Tries HTTPS first, then falls back to HTTP.
    Matches browser behavior to avoid false negatives.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    # 1. Try HTTPS (Port 443) - Most likely to work
    try:
        url = f"https://{subdomain}"
        # ssl=False ignores certificate errors (self-signed is still 'UP')
        async with session.get(url, headers=headers, timeout=5, ssl=False, allow_redirects=True) as resp:
            return {
                'subdomain': subdomain,
                'status': resp.status,
                'is_up': True,
                'url': str(resp.url)
            }
    except:
        # 2. Fallback to HTTP (Port 80) if HTTPS fails connection
        try:
            url = f"http://{subdomain}"
            async with session.get(url, headers=headers, timeout=5, allow_redirects=True) as resp:
                return {
                    'subdomain': subdomain,
                    'status': resp.status,
                    'is_up': True,
                    'url': str(resp.url)
                }
        except:
            # Both failed
            return {
                'subdomain': subdomain,
                'status': 'DOWN',
                'is_up': False,
                'url': url
            }

async def validate_subdomains(subdomain_list):
    """
    Checks a list of subdomains concurrently.
    """
    connector = aiohttp.TCPConnector(limit=50) # Limit concurrent connections
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for sub in subdomain_list:
            tasks.append(check_domain_status(session, sub))
        
        # Run all checks
        results = await asyncio.gather(*tasks)
        
    # Sort: Alive sites first
    results.sort(key=lambda x: x['is_up'], reverse=True)
    return results


# ==========================================
# 6. FLASK ROUTES
# ==========================================

# --- [NEW] LOGIN ROUTE (Root URL) ---
@app.route('/')
def login_page():
    return render_template('login.html')

# --- [NEW] DASHBOARD ROUTE (Renamed from index) ---
@app.route('/dashboard')
def dashboard():
    return render_template('index.html', vulnerabilities=vulnerabilities)

@app.route('/tool/<vulnerability_id>')
def tool_page(vulnerability_id):
    vulnerability = vulnerabilities.get(vulnerability_id)
    if not vulnerability:
        return redirect(url_for('dashboard')) # Redirect to dashboard if invalid tool
    return render_template('tool_page.html', vulnerability=vulnerability, vuln_id=vulnerability_id)

# --- CSRF Route ---
@app.route('/scan/csrf', methods=['POST'])
def scan_csrf():
    url_to_scan = request.form.get('url')
    scan_results = {'url': url_to_scan, 'forms': [], 'headers': {}, 'error': None}
    try:
        forms, headers = get_forms(url_to_scan)
        if not forms: scan_results['error'] = "No forms found."
        for i, f in enumerate(forms, 1):
            has_token, token_name = has_csrf_token(f['inputs'])
            scan_results['forms'].append({'id': i, 'action': f['action'], 'method': f['method'].upper(), 'has_token': has_token, 'token_name': token_name})
        for h in ['x-frame-options', 'x-content-type-options', 'content-security-policy']:
            scan_results['headers'][h] = headers.get(h, 'NOT SET')
    except Exception as e: scan_results['error'] = f"Error: {e}"
    return render_template('results_page.html', results=scan_results)

# --- IDOR Route ---
@app.route('/scan/idor', methods=['POST'])
def scan_idor_route():
    url_template = request.form.get('url_template')
    start_id = request.form.get('start_id', 1, type=int)
    end_id = request.form.get('end_id', 20, type=int)
    if end_id - start_id > 100: end_id = start_id + 100
    scan_results = scan_idor(url_template, start_id, end_id)
    return render_template('idor_results_page.html', results=scan_results, template=url_template)

# --- SQLi Route ---
@app.route("/scan/sqli", methods=["POST"])
def scan_sqli():
    url = request.form.get("url")
    scanner = SQLiScanner(url)
    findings = asyncio.run(scanner.scan())
    return render_template('sqli_results_page.html', url=url, findings=findings)

# --- XSS Advanced Route ---
@app.route('/scan/xss_adv', methods=['POST'])
def scan_xss_adv_route():
    target_url = request.form.get('url')
    params = request.form.get('params')
    methods = request.form.get('methods') or 'GET'
    timeout = request.form.get('timeout', type=int) or 12
    threads = request.form.get('threads', type=int) or 8
    crawl = request.form.get('crawl') == 'on'
    
    param_list = [p.strip() for p in params.split(',')] if params else None
    method_list = [m.strip().upper() for m in methods.split(',') if m.strip()]
    
    scan = run_advanced_xss_scan(
        base_url=target_url,
        param_list=param_list,
        test_methods=method_list,
        timeout=timeout,
        max_workers=threads,
        crawl=crawl
    )
    return render_template('xss_adv_results_page.html', results=scan)

# --- Subdomain Scanner Route ---
@app.route('/scan/subdomains', methods=['POST'])
def scan_subdomains_route():
    domain = request.form.get('domain')
    # Clean input
    if not domain: return "Domain required", 400
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # 1. Passive Scan
    passive_results = scan_subdomains_passive(domain)
    
    # Check for passive errors
    if isinstance(passive_results, dict) and 'error' in passive_results:
        return render_template('subdomain_results_page.html', domain=domain, subdomains=[], error=passive_results['error'])
    
    # 2. Active Validation (Limit first 100 for speed)
    subdomains_to_check = passive_results[:100] 
    active_results = asyncio.run(validate_subdomains(subdomains_to_check))
    
    return render_template('subdomain_results_page.html', domain=domain, subdomains=active_results, error=None)

if __name__ == '__main__':
    app.run(debug=True)