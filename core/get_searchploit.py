import subprocess
import json

def get_exploits(product, version):
    """
    Searchsploit을 사용하여 product와 version에 해당하는 취약점을 검색합니다.
    """
    # query = f"{product} {version}"
    query = f"{'OpenEMR'} {'7.0.2'}"
    try:
        cmd = ['searchsploit', '--json'] + query.split()
        # --json 옵션으로 검색 결과를 JSON 포맷으로 출력
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True
        )
        print(result.stdout)
        # 결과가 없거나 오류가 발생할 경우 대비
        if result.returncode == 0:
            stdout_data = result.stdout.strip()
            if stdout_data:
                try:
                    data = json.loads(stdout_data)
                    # 여기서 데이터를 다뤄야 합니다.
                    print(f"DEBUG: Found {len(data.get('RESULTS_EXPLOIT', []))} exploits.")
                    return data.get('RESULTS_EXPLOIT', [])
                except json.JSONDecodeError:
                    print("[-] JSON 파싱 실패: 출력값이 JSON 형식이 아닙니다.")
                    return []
            
        data = json.loads(result.stdout)
        # 결과 리스트 반환
        print(data)
        return data.get('RESULTS_EXPLOIT', [])
    except Exception as e:
        print(f"[!] Searchsploit 실행 중 오류 발생: {e}")
        return []