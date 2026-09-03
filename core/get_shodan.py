import shodan
import os
import socket


COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP',
    3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP Alternate',
}

def run_security_scan(ip, API_KEY):
    """
    Shodan API를 사용하여 해당 IP의 서비스 정보
    {
        'ip': '13.59.93.103',
        'host_info': {'isp': 'Amazon.com, Inc.', 'os': 'Amazon', 'hostnames': ['lsc.comrex.com', 'sb-balancer.comrex.com'], 'org': 'Amazon Technologies Inc.'},  # 호스트 정보는 한 번만 저장
        'services':  [{'port': 80, 'product': 'Microsoft IIS', 'version': '6.0', 'server': 'Unknown', 'transport': 'tcp', 'cpe': [], 'banner': 'HTTP/1.1 302 Found\r\nCache-Control: no-cache\r\nContent-length: 0\r\nLocation: https://13.59.93.103/\r\n\r\n'}]
    }
    """
    api = shodan.Shodan(API_KEY)
    
    try:
        host = api.host(ip)

        host_info = {
                'isp': host.get('isp', 'Unknown'),
                'os': host.get('os', 'Unknown'),
                'hostnames': host.get('hostnames', []),
                'org': host.get('org', 'Unknown')
            }
        
        services = []    
        
        for item in host['data']:
            # print(host['data'])
            services.append({
                'port': item['port'],
                'product': item.get('product', 'Unknown'),
                'version': item.get('version', 'Unknown'),
                'server' : item.get('server', 'Unknown'),
                'transport': item.get('transport', 'tcp'),
                'cpe': item.get('cpe', []),
                'banner': item.get('data', '')
            })

        return {
            'ip': ip,
            'host_info': host_info,  # 호스트 정보는 한 번만 저장
            'services': services         # 포트 정보만 리스트로 저장
        }
    
    except Exception as e:
        print(f"[!] Shodan API 오류: {e}")
        return None


def build_unindexed_target_result(target, ip, timeout=0.75):
    """Create a manual-check result when Shodan has no host record.

    The fallback only performs small TCP reachability checks; it does not
    fingerprint services or attempt exploitation.
    """
    try:
        dns_addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(target, None)})
    except socket.gaierror:
        dns_addresses = [ip]

    port_status = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                status = 'open'
        except (socket.timeout, ConnectionRefusedError, OSError):
            status = 'closed or filtered'
        port_status.append({'port': port, 'service': service, 'status': status})

    return {
        'ip': ip,
        'host_info': {
            'isp': 'Unavailable (not indexed by Shodan)',
            'os': 'Unknown',
            'hostnames': [target],
            'org': 'Unavailable (not indexed by Shodan)',
        },
        'services': [{
            'port': 'N/A',
            'product': 'Unknown',
            'version': 'Unknown',
            'server': 'Unavailable (not indexed by Shodan)',
            'transport': 'tcp',
            'cpe': [],
            'banner': '',
            'dns_addresses': dns_addresses,
            'port_status': port_status,
            'scan_note': (
                'Shodan has no host record for this IP. Review reachable ports '
                'manually; no vulnerability conclusion was made.'
            ),
        }],
    }
