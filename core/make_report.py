from fpdf import FPDF
from datetime import datetime
from pathlib import Path
import re

PROJECT_DIR = Path(__file__).resolve().parents[1]


def _pdf_text(value):
    """Make external banner/metadata text safe for FPDF's built-in fonts."""
    return str(value).encode("latin-1", errors="replace").decode("latin-1")

def generate_pdf_report(target, findings):
    output_dir = PROJECT_DIR / "output"
    output_dir.mkdir(exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("._") or "target"
    filename = output_dir / f"{date_str}_{safe_target}_report.pdf"
    
    pdf = FPDF()
    pdf.add_page()
    
    # 헤더
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt=_pdf_text(f"Security Scan Report: {target}"), ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)
    
    if findings:
        host_data = findings[0].get('raw_data', {})
        # ISP, OS, Org, Hostnames만 따로 뽑아내기
        host_summary = {
            'ISP': host_data.get('isp', 'N/A'),
            'OS': host_data.get('os', 'N/A'),
            'Organization': host_data.get('organization', 'N/A'),
            'Hostnames': host_data.get('hostnames', 'N/A')
        }
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Host Global Information", ln=True, border='B')
        pdf.set_font("Arial", '', 10)
        for key, val in host_summary.items():
            pdf.cell(200, 6, txt=_pdf_text(f"{key}: {val}"), ln=True)
        pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Port Services Analysis", ln=True, border='B')
    pdf.ln(5)    

    # 데이터 기록
    for f in findings:
        port = f.get('port', 'N/A')
        prod = f.get('product', 'Unknown')
        vers = f.get('version', 'Unknown')
        msg = f.get('msg','Unknown')
        
        # 1. 포트 서비스 헤더
        pdf.set_font("Arial", 'B', 12)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(200, 10, txt=_pdf_text(f"Port: {port} | Product: {prod} ({vers})"), ln=True, fill=True)
        
        # 2. 상세 정보(raw_data) 출력
        raw_data = f.get('raw_data', {})
        service_specific = {k: v for k, v in raw_data.items() 
                            if k not in ['isp', 'os', 'organization', 'hostnames']}
        
        for key, val in service_specific.items():
            pdf.set_font("Arial", 'I', 9) 
            pdf.set_text_color(100, 100, 100) 

            # 'banner' 키인지 확인하여 별도 처리
            if key.lower() == 'banner' and val:
                pdf.ln(2)
                pdf.set_font("Courier", '', 8) 
                pdf.set_fill_color(245, 245, 245) 
                pdf.set_text_color(50, 50, 50)
                
                # 배너 텍스트를 여러 줄로 출력 (코드 박스 느낌)
                pdf.multi_cell(0, 5, txt=_pdf_text(val), border=1, fill=True)
                
                pdf.ln(2)
                pdf.set_font("Arial", 'I', 9) 
                pdf.set_text_color(100, 100, 100)
            else:
                # 일반 상세 정보 출력
                if key.lower() == 'port_status' and isinstance(val, list):
                    display_val = "; ".join(
                        f"{item.get('port')}/{item.get('service')}: {item.get('status')}"
                        for item in val
                    )
                elif isinstance(val, list):
                    display_val = ", ".join(map(str, val))
                else:
                    display_val = str(val)
                if key.lower() == 'port_status':
                    pdf.multi_cell(200, 5, txt=_pdf_text(f"  {key.upper()}: {display_val}"))
                else:
                    pdf.cell(200, 5, txt=_pdf_text(f"  {key.upper()}: {display_val}"), ln=True)
        
            pdf.set_text_color(0, 0, 0) 
            pdf.ln(2)
        
        # 3. 취약점 정보 출력
        pdf.set_font("Arial", size=10)
        exploits = f.get('exploits', [])
        if exploits:
            pdf.set_font("Arial", 'B', 10)
            pdf.set_text_color(180, 0, 0)
            pdf.cell(0, 8, txt="Known Vulnerabilities Table:", ln=True)
            
            # 표 헤더
            pdf.set_fill_color(200, 200, 200)
            pdf.set_font("Arial", 'B', 9)
            pdf.cell(30, 7, "ID", border=1, fill=True)
            pdf.cell(100, 7, "Description", border=1, fill=True)
            pdf.cell(60, 7, "File Path", border=1, fill=True, ln=True)
            
            # 표 내용
            pdf.set_font("Arial", '', 8)
            pdf.set_text_color(0, 0, 0)
            for exp in exploits:
                # 데이터가 길 경우를 대비해 multi_cell 대신 cell 사용 (줄바꿈이 필요하면 logic 조정)
                pdf.cell(30, 7, _pdf_text(exp.get('id', '')), border=1)
                
                # description이 길면 잘릴 수 있으므로, 폰트 조절 또는 multi_cell 조합 필요
                # 일단 간단한 표현 방식:
                pdf.cell(100, 7, _pdf_text(exp.get('description', 'No Title'))[:55], border=1)
                pdf.cell(60, 7, _pdf_text(exp.get('file', 'No Path'))[-35:], border=1, ln=True)
                
            pdf.ln(5)
        else:
            # 취약점 없을 때의 메시지
            pdf.set_font("Arial", 'I', 10)
            pdf.cell(200, 5, txt=f"Status: {msg}", ln=True)
        pdf.ln(5)
        
    pdf.output(str(filename))
    return str(filename)
