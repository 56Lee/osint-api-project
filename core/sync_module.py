import requests
import tempfile
from pathlib import Path

CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
# 파일 메타데이터를 가져오는 API 호출 (커밋 정보 포함)
API_URL = "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/files/files_exploits.csv?ref=main"
PROJECT_DIR = Path(__file__).resolve().parents[1]
LOCAL_FILE = PROJECT_DIR / "files_exploits.csv"
COMMIT_FILE = PROJECT_DIR / "last_commit.txt"
REQUEST_TIMEOUT = 30

def get_remote_last_commit_id():
    """GitLab API를 통해 파일의 마지막 커밋 ID를 가져옵니다."""
    try:
        response = requests.get(API_URL, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            return data.get('last_commit_id')
        return None
    except requests.RequestException as e:
        print(f"[!] 서버 연결 오류: {e}")
        return None

def get_local_commit_id():
    """로컬에 저장된 마지막 커밋 ID를 읽어옵니다."""
    if COMMIT_FILE.exists():
        with COMMIT_FILE.open('r', encoding='utf-8') as f:
            return f.read().strip()
    return None

def save_local_commit_id(commit_id):
    """현재 커밋 ID를 로컬에 저장합니다."""
    with COMMIT_FILE.open('w', encoding='utf-8') as f:
        f.write(commit_id)

def download_exploit_db(commit_id):
    """파일을 다운로드하고 커밋 ID를 갱신합니다."""
    print("[*] 새 버전이 감지되었습니다. 다운로드 중...")
    temp_path = None
    try:
        response = requests.get(CSV_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        if not response.content.startswith(b"id,file,description"):
            raise ValueError("다운로드한 파일이 Exploit-DB CSV 형식이 아닙니다.")
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=PROJECT_DIR) as tmp:
            tmp.write(response.content)
            temp_path = Path(tmp.name)
        temp_path.replace(LOCAL_FILE)
        save_local_commit_id(commit_id)
        print("[+] 다운로드 및 동기화 완료!")
        return True
    except (requests.RequestException, OSError, ValueError) as exc:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        print(f"[!] 다운로드 실패: {exc}")
        return False

def sync_exploit_db():
    """데이터 확인 및 동기화 메인 함수"""
    remote_commit = get_remote_last_commit_id()
    local_commit = get_local_commit_id()

    if not remote_commit:
        print("[!] 원격 서버에서 커밋 정보를 가져올 수 없습니다.")
        return

    # 로컬 파일이 없거나 커밋 ID가 다르면 다운로드
    if not LOCAL_FILE.exists() or remote_commit != local_commit:
        return download_exploit_db(remote_commit)
    else:
        print("[+] 로컬 데이터베이스가 최신 버전입니다.")
        return True
