STATUS_CLEAN = 'Clean'
STATUS_VULNERABLE = 'Vulnerable'
STATUS_MANUAL = 'Manual Check'

def create_finding_result(port, product, version, status, msg, exploits=None, raw_data=None):
    return {
        'port': port,
        'product': product,
        'version': version,
        'status': status,
        'msg': msg,
        'exploits': exploits if exploits else [],
        'raw_data': raw_data if raw_data else {} 
    }


def clean_raw_data(raw_data):
    """보고서에 담을 핵심 정보만 추출합니다."""
    if not raw_data:
        return {}
    host_info = raw_data.get('host_info', {})

    cleaned = {
            'transport' : raw_data.get('transport'),
            'cpe' : raw_data.get('cpe'),
            'os': host_info.get('os'),
            'isp': host_info.get('isp'),
            'organization': host_info.get('org'),
            'hostnames': host_info.get('hostnames'),
            'server': raw_data.get('server'),
            'banner' : raw_data.get('banner'),
            'dns_addresses': raw_data.get('dns_addresses'),
            'port_status': raw_data.get('port_status'),
            'scan_note': raw_data.get('scan_note'),
        }
        
    return cleaned
