# modules/config_audit.py
from modules.azure_ai import ask_azure_openai
import json

def extract_must_check_configs(ps_output, cve_json, logger=None):
    prompt = (
        "아래는 리눅스 서버에서 웹서버 구동 프로세스 목록(ps)와 CVE 취약점 json입니다.\n"
        "CVE json의 내용을 참고해, 반드시 점검이 필요한 설정파일의 전체 경로만 쉼표(,)로 구분해서 반환하세요. 설명 없이 경로만 반환.\n"
        "---ps---\n"
        f"{ps_output}\n"
        "---cve---\n"
        f"{json.dumps(cve_json, ensure_ascii=False, indent=2)}"
    )
    messages = [
        {"role": "system", "content": "당신은 리눅스/웹서버 보안 취약점 전문가입니다."},
        {"role": "user", "content": prompt}
    ]
    return ask_azure_openai(messages, logger)

def audit_config_with_cve(cve_json, config_path, config_content, logger=None):
    prompt = (
        f"아래는 특정 CVE 취약점 json 데이터와 {config_path} 파일 내용입니다.\n"
        f"이 설정파일에 해당 CVE의 취약점이 존재하는지, 문제의 원인, 필요한 조치방법을 최대한 간단명료하게 한국어로 진단/권고해줘."
        f"\n---cve---\n{json.dumps(cve_json, ensure_ascii=False, indent=2)}"
        f"\n---config---\n{config_content}"
    )
    messages = [
        {"role": "system", "content": "당신은 리눅스/웹서버 보안 전문가입니다."},
        {"role": "user", "content": prompt}
    ]
    return ask_azure_openai(messages, logger)
