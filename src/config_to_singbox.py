import json
import base64
import uuid
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/sb.json'

    def decode_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            decoded = base64.b64decode(encoded).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'vless' or not url.hostname:
                return None
            
            netloc = url.netloc.split('@')[-1]
            address, port = netloc.split(':') if ':' in netloc else (netloc, '443')
            params = parse_qs(url.query)
            
            return {
                'uuid': url.username,
                'address': address,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [address])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0]
            }
        except:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'trojan' or not url.hostname:
                return None
            
            port = url.port or 443
            params = parse_qs(url.query)
            
            return {
                'password': url.username,
                'address': url.hostname,
                'port': port,
                'sni': params.get('sni', [url.hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0]
            }
        except:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config.replace('hysteria2://', '').replace('hy2://', ''))
            if not url.hostname or not url.port:
                return None
                
            query = dict(pair.split('=') for pair in url.query.split('&')) if url.query else {}
            
            return {
                'address': url.hostname,
                'port': url.port,
                'password': url.username or query.get('password', ''),
                'sni': query.get('sni', url.hostname)
            }
        except:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
                
            method_pass = base64.b64decode(parts[0]).decode('utf-8')
            method, password = method_pass.split(':')
            
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            
            return {
                'method': method,
                'password': password,
                'address': host,
                'port': int(port)
            }
        except:
            return None

    def convert_to_singbox(self, config: str) -> Optional[Dict]:
        try:
            if config.startswith('vmess://'):
                vmess_data = self.decode_vmess(config)
                if not vmess_data or not vmess_data.get('add') or not vmess_data.get('port') or not vmess_data.get('id'):
                    return None
                
                return {
                    "type": "vmess",
                    "tag": f"vmess-{str(uuid.uuid4())[:8]}",
                    "server": vmess_data['add'],
                    "server_port": int(vmess_data['port']),
                    "uuid": vmess_data['id'],
                    "security": vmess_data.get('scy', 'auto'),
                    "alter_id": int(vmess_data.get('aid', 0)),
                    "transport": {
                        "type": vmess_data.get('net', 'tcp'),
                        "path": vmess_data.get('path', ''),
                        "headers": {"Host": vmess_data.get('host', '')}
                    } if vmess_data.get('net') in ['ws', 'h2'] else {},
                    "tls": {
                        "enabled": vmess_data.get('tls') == 'tls',
                        "insecure": True,
                        "server_name": vmess_data.get('sni', vmess_data['add'])
                    }
                }

            elif config.startswith('vless://'):
                vless_data = self.parse_vless(config)
                if not vless_data:
                    return None
                
                out = {
                    "type": "vless",
                    "tag": f"vless-{str(uuid.uuid4())[:8]}",
                    "server": vless_data['address'],
                    "server_port": vless_data['port'],
                    "uuid": vless_data['uuid'],
                    "flow": vless_data['flow'],
                    "tls": {
                        "enabled": True,
                        "server_name": vless_data['sni'],
                        "insecure": True
                    },
                    "transport": {}
                }
                
                if vless_data['type'] == 'ws':
                    out['transport'] = {
                        "type": "ws",
                        "path": vless_data['path'],
                        "headers": {"Host": vless_data['host']}
                    }
                return out

            elif config.startswith('trojan://'):
                trojan_data = self.parse_trojan(config)
                if not trojan_data:
                    return None
                
                return {
                    "type": "trojan",
                    "tag": f"trojan-{str(uuid.uuid4())[:8]}",
                    "server": trojan_data['address'],
                    "server_port": trojan_data['port'],
                    "password": trojan_data['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": trojan_data['sni'],
                        "alpn": trojan_data['alpn'].split(',') if trojan_data['alpn'] else [],
                        "insecure": True
                    },
                    "transport": {
                        "type": trojan_data['type'],
                        "path": trojan_data['path']
                    } if trojan_data['type'] != 'tcp' else {}
                }

            elif config.startswith(('hysteria2://', 'hy2://')):
                hy2_data = self.parse_hysteria2(config)
                if not hy2_data or not hy2_data['address'] or not hy2_data['port'] or not hy2_data['password']:
                    return None
                
                return {
                    "type": "hysteria2",
                    "tag": f"hysteria2-{str(uuid.uuid4())[:8]}",
                    "server": hy2_data['address'],
                    "server_port": hy2_data['port'],
                    "password": hy2_data['password'],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": hy2_data['sni']
                    }
                }

            elif config.startswith('ss://'):
                ss_data = self.parse_shadowsocks(config)
                if not ss_data or not ss_data['address'] or not ss_data['port']:
                    return None
                
                return {
                    "type": "shadowsocks",
                    "tag": f"ss-{str(uuid.uuid4())[:8]}",
                    "server": ss_data['address'],
                    "server_port": ss_data['port'],
                    "method": ss_data['method'],
                    "password": ss_data['password']
                }

            return None
        except:
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs.txt', 'r') as f:
                configs = f.read().strip().split('\n')

            outbounds = []
            valid_tags = []

            for config in configs:
                config = config.strip()
                if not config or config.startswith('//'):
                    continue
                    
                converted = self.convert_to_singbox(config)
                if converted:
                    outbounds.append(converted)
                    valid_tags.append(converted['tag'])

            if not outbounds:
                return

            singbox_config = {
                "dns": {
                    "final": "local-dns",
                    "rules": [
                        {
                            "clash_mode": "Global",
                            "server": "proxy-dns",
                            "source_ip_cidr": ["172.19.0.0/30"]
                        },
                        {
                            "server": "proxy-dns",
                            "source_ip_cidr": ["172.19.0.0/30"]
                        },
                        {
                            "clash_mode": "Direct",
                            "server": "direct-dns"
                        },
                        {
                            "rule_set": ["geosite-ir"],
                            "server": "direct-dns"
                        }
                    ],
                    "servers": [
                        {
                            "address": "tls://208.67.222.123",
                            "address_resolver": "local-dns",
                            "detour": "proxy",
                            "tag": "proxy-dns"
                        },
                        {
                            "address": "local",
                            "detour": "direct",
                            "tag": "local-dns"
                        },
                        {
                            "address": "rcode://success",
                            "tag": "block"
                        },
                        {
                            "address": "local",
                            "detour": "direct",
                            "tag": "direct-dns"
                        }
                    ],
                    "strategy": "prefer_ipv4"
                },
                "inbounds": [
                    {
                        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                        "auto_route": True,
                        "endpoint_independent_nat": False,
                        "mtu": 9000,
                        "platform": {
                            "http_proxy": {
                                "enabled": True,
                                "server": "127.0.0.1",
                                "server_port": 2080
                            }
                        },
                        "sniff": True,
                        "stack": "system",
                        "strict_route": False,
                        "type": "tun"
                    },
                    {
                        "listen": "127.0.0.1",
                        "listen_port": 2080,
                        "sniff": True,
                        "type": "mixed",
                        "users": []
                    }
                ],
                "outbounds": [
                    {
                        "tag": "proxy",
                        "type": "selector",
                        "outbounds": ["auto"] + valid_tags + ["direct"]
                    },
                    {
                        "tag": "auto",
                        "type": "urltest",
                        "outbounds": valid_tags,
                        "url": "http://www.gstatic.com/generate_204",
                        "interval": "10m",
                        "tolerance": 50
                    },
                    {
                        "tag": "direct",
                        "type": "direct"
                    },
                    {
                        "tag": "dns-out",
                        "type": "dns"
                    },
                    {
                        "tag": "block",
                        "type": "block"
                    }
                ] + outbounds,
                "route": {
                    "auto_detect_interface": True,
                    "final": "proxy",
                    "rule_set": [
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geosite-ads",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geosite-private",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/private.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geosite-ir",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ir.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geoip-private",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/private.srs"
                        },
                        {
                            "download_detour": "direct",
                            "format": "binary",
                            "tag": "geoip-ir",
                            "type": "remote",
                            "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/ir.srs"
                        }
                    ],
                    "rules": [
                        {
                            "clash_mode": "Direct",
                            "outbound": "direct"
                        },
                        {
                            "clash_mode": "Global",
                            "outbound": "proxy"
                        },
                        {
                            "outbound": "dns-out",
                            "protocol": "dns"
                        },
                        {
                            "outbound": "direct",
                            "rule_set": [
                                "geoip-private",
                                "geosite-private",
                                "geosite-ir",
                                "geoip-ir"
                            ]
                        },
                        {
                            "outbound": "block",
                            "rule_set": ["geosite-ads"]
                        }
                    ]
                }
            }

            with open(self.output_file, 'w') as f:
                json.dump(singbox_config, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()
if __name__ == '__main__':
    main()
