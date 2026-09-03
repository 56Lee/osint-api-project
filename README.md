# OSINT Security Report

Shodan에서 공개 서비스 정보를 가져오고 NVD, CISA KEV, Exploit-DB를 대조해 PDF 점검 보고서를 생성하는 Python CLI입니다.

> 본인 소유이거나 명시적으로 점검 허가를 받은 대상에만 사용하세요.

## 설치

Python 3.10 이상을 권장합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

`.env`의 `SHODAN_API_KEY` 값을 실제 키로 바꿉니다.

## 실행

```powershell
python main.py example.com
```

대상을 생략하면 대화형으로 입력할 수 있습니다. 최초 실행 시 공식 Exploit-DB 저장소에서 최신 CSV를 내려받으며, 이 데이터 파일은 Git에 포함되지 않습니다. 이미 내려받은 CSV를 사용하려면 `python main.py example.com --skip-db-sync`를 실행합니다. 보고서는 `output/`에 저장됩니다.

## 데이터 출처

- Exploit-DB CSV: <https://gitlab.com/exploit-database/exploitdb>
- NVD CVE API: <https://nvd.nist.gov/developers/vulnerabilities>
- CISA KEV Catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

외부 데이터는 각 제공자의 정책과 라이선스를 따르며 저장소에는 원본 데이터 사본을 배포하지 않습니다.
