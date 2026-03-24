#!/usr/bin/env python3
"""
IP风险分析工具 - 本地服务器
用法：python3 server.py
会自动打开浏览器访问 http://localhost:8888
"""
import http.server, json, os, sys, threading, webbrowser, requests

PORT = 8888
DIR  = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=DIR, **kw)

    def log_message(self, fmt, *args):
        # 只打印非静态资源请求
        if '/api/' in args[0] if args else False:
            print(f"  {args[0]}")

    def do_OPTIONS(self):
        self.send_response(200)
        origin = self.headers.get('Origin', '')
        self._cors(origin)
        self.end_headers()

    def do_GET(self):
        # /api/ip/<ip> → 代理查询 freeipapi.com，备用 ipwho.is
        if self.path.startswith('/api/ip/'):
            ip = self.path.split('/api/ip/')[-1].split('?')[0].strip()
            result = self._query_ip(ip)
            body = json.dumps(result).encode()
            self.send_response(200)
            origin = self.headers.get('Origin', '')
            self._cors(origin)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()

    def _cors(self, origin=None):
        # 只允许本机来源，防止其他域名的恶意请求
        allowed = ['http://localhost:8888', 'http://127.0.0.1:8888',
                   'https://localhost:8888', 'https://127.0.0.1:8888']
        # 过滤换行符，防止 HTTP 响应拆分攻击
        safe_origin = origin.replace('\r', '').replace('\n', '') if origin else ''
        if safe_origin and safe_origin in allowed:
            self.send_header('Access-Control-Allow-Origin', safe_origin)
        else:
            self.send_header('Access-Control-Allow-Origin', 'http://localhost:8888')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Vary', 'Origin')

    def _sanitize_ip(self, ip):
        import re
        ip = str(ip).strip()
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            if all(0 <= int(p) <= 255 for p in ip.split('.')):
                return ip
        if re.match(r'^[0-9a-fA-F:]{2,39}$', ip):
            return ip
        return None

    def _query_ip(self, ip):
        ip = self._sanitize_ip(ip)
        if not ip:
            return {'cc': '', 'country': 'invalid IP', 'city': '', 'region': '', 'org': '', 'source': ''}
        # 接口1: freeipapi.com
        try:
            r = requests.get(
                f'https://freeipapi.com/api/json/{ip}',
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=5
            )
            d = r.json()
            if d.get('countryCode') and d['countryCode'] != '-':
                return {
                    'cc': d['countryCode'],
                    'country': d.get('countryName', ''),
                    'city': d.get('cityName', ''),
                    'region': d.get('regionName', ''),
                    'org': d.get('ipType', ''),
                    'source': 'freeipapi.com'
                }
        except Exception as e:
            print(f"  freeipapi failed for {ip}: {e}")

        # 接口2: ipwho.is
        try:
            r = requests.get(
                f'https://ipwho.is/{ip}',
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=5
            )
            d = r.json()
            if d.get('success') and d.get('country_code'):
                conn = d.get('connection') or {}
                return {
                    'cc': d['country_code'],
                    'country': d.get('country', ''),
                    'city': d.get('city', ''),
                    'region': d.get('region', ''),
                    'org': conn.get('isp') or conn.get('org') or '',
                    'source': 'ipwho.is'
                }
        except Exception as e:
            print(f"  ipwho.is failed for {ip}: {e}")

        # 接口3: ip-api.com
        try:
            r = requests.get(
                f'https://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,countryCode,regionName,city,isp',
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=5
            )
            d = r.json()
            if d.get('status') == 'success':
                return {
                    'cc': d.get('countryCode', ''),
                    'country': d.get('country', ''),
                    'city': d.get('city', ''),
                    'region': d.get('regionName', ''),
                    'org': d.get('isp', ''),
                    'source': 'ip-api.com'
                }
        except Exception as e:
            print(f"  ip-api.com failed for {ip}: {e}")

        return {'cc': '', 'country': '查询失败', 'city': '', 'region': '', 'org': '', 'source': ''}


def main():
    url = f'http://localhost:{PORT}/ip-risk-analyzer.html'
    server = http.server.HTTPServer(('localhost', PORT), Handler)
    print(f"""
╔══════════════════════════════════════════╗
║     IP 风险分析工具 - 本地服务器         ║
╠══════════════════════════════════════════╣
║  地址: http://localhost:{PORT}              ║
║  停止: Ctrl+C                            ║
╚══════════════════════════════════════════╝
""")
    # 延迟1秒后打开浏览器
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")

if __name__ == '__main__':
    main()
