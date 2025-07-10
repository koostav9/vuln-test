import requests
import json
from modules.azure_ai import ask_azure_openai

def get_cve_info_azure(cve_id, logger=None):
    cve_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        if logger:
            logger.info(f"CVE 조회 요청: {cve_id}")
        res = requests.get(cve_url, timeout=8)
        if res.status_code != 200:
            if logger:
                logger.warning(f"CVE 조회 실패 (상태코드: {res.status_code})")
            return None
        cve_json = res.json()
        if logger:
            logger.info(f"AzureOpenAI로 CVE 정보 전달")
        prompt = (
            "아래는 CVE 취약점 API의 전체 JSON입니다. "
            "중요한 취약점 요약, 영향, CVSS, 패치 권고 등 핵심 내용만 한국어로 보기 좋게 정리해서 10줄 이내로 알려줘.\n"
            "-----\n"
            + json.dumps(cve_json, ensure_ascii=False, indent=2)
        )
        messages = [
            {"role": "system", "content": "당신은 보안 취약점 분석 전문가입니다."},
            {"role": "user", "content": prompt}
        ]
        answer = ask_azure_openai(messages, logger)
        return answer
    except Exception as e:
        if logger:
            logger.error(f"CVE+AzureOpenAI 처리 중 오류: {e}")
        return None
