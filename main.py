import argparse
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv
from core.get_shodan import run_security_scan, build_unindexed_target_result
from core.get_exploitsfile import ExploitSearcher
from core.make_report import generate_pdf_report  
from core.sync_module import sync_exploit_db
from core.formatter import create_finding_result, clean_raw_data, STATUS_CLEAN, STATUS_VULNERABLE, STATUS_MANUAL


# 설정 로드
PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")
API_KEY = os.getenv('SHODAN_API_KEY')


def initialize_system():
    """시스템 초기화 및 데이터베이스 준비"""
    print("[*] 데이터베이스 상태를 확인합니다...")
    sync_exploit_db()
    searcher = ExploitSearcher(PROJECT_DIR / "files_exploits.csv")
    if not searcher.load_data():
        print("[-] 데이터베이스 로드 실패.")
        return None
    return searcher


def resolve_target(target):
    """대상 도메인/IP 해석"""
    target = target.strip()
    if "://" in target:
        target = urlsplit(target).hostname or ""
    elif target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            target = host
    try:
        return socket.gethostbyname(target)
    except (socket.gaierror, UnicodeError):
        return None


def analyze_services(services, searcher):
    """서비스별 취약점 분석 로직"""
    all_findings = []
    for s in services:
        product, version = s.get('product'), s.get('version')
        
        if product == 'Unknown' or version == 'Unknown':
            finding = create_finding_result(
                s['port'], 
                product, 
                version, 
                STATUS_MANUAL,   
                "Version identification failed.", 
                raw_data=clean_raw_data(s)
                )
        else:
            exploits = searcher.search_exploits(product, version, s.get('cpe'))
            if exploits is None:
                finding = create_finding_result(
                    s['port'], product, version, STATUS_MANUAL,
                    "Vulnerability sources were unavailable; manual verification required.",
                    raw_data=clean_raw_data(s),
                )
            elif not exploits.empty:
                kev_count = int(exploits.get('known_exploited', []).sum()) if 'known_exploited' in exploits else 0
                kev_suffix = f" ({kev_count} actively exploited)" if kev_count else ""
                finding = create_finding_result(
                    s['port'], 
                    product, 
                    version, 
                    STATUS_VULNERABLE, 
                    f"{len(exploits)} Vulnerabilities detected.{kev_suffix}", 
                    exploits.to_dict('records'), 
                    raw_data=clean_raw_data(s)
                    )
            else:
                finding = create_finding_result(
                    s['port'], 
                    product, 
                    version, 
                    STATUS_CLEAN, 
                    "No known vulnerabilities found.", 
                    raw_data=clean_raw_data(s)
                    )
        all_findings.append(finding)
    return all_findings


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Shodan, NVD, CISA KEV를 활용해 공개 서비스의 취약점을 점검합니다."
    )
    parser.add_argument("target", nargs="?", help="분석할 도메인, IP 또는 URL")
    parser.add_argument("--skip-db-sync", action="store_true", help="로컬 Exploit-DB CSV를 갱신하지 않습니다.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not API_KEY:
        print("[-] SHODAN_API_KEY가 없습니다. .env 파일 또는 환경 변수에 설정하세요.")
        return 2

    if args.skip_db_sync:
        searcher = ExploitSearcher(PROJECT_DIR / "files_exploits.csv")
        searcher = searcher if searcher.load_data() else None
    else:
        searcher = initialize_system()
    if not searcher:
        return 1

    target = args.target or input("[*] 분석할 도메인 또는 IP를 입력하세요: ").strip()
    if not target:
        print("[-] 입력값이 없습니다.")
        return 2

    target_ip = resolve_target(target)
    if not target_ip:
        print("[!] 유효하지 않은 대상입니다.")
        return 2

    print(f"[+] '{target}' 분석 시작 ({target_ip})...")
    results = run_security_scan(target_ip, API_KEY)
    
    if results and 'services' in results:
        findings = analyze_services(results['services'], searcher)
        if findings:
            report_path = generate_pdf_report(target, findings)
            print(f"\n[+] 보고서 생성이 완료되었습니다: {report_path}")
    else:
        print("[!] Shodan information is unavailable. Creating a manual-check report.")
        fallback_results = build_unindexed_target_result(target, target_ip)
        findings = analyze_services(fallback_results['services'], searcher)
        report_path = generate_pdf_report(target, findings)
        print(f"[+] Manual-check report created: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

