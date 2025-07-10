import paramiko
import requests
import json
from modules.azure_ai import ask_azure_openai

def audit_server_with_cve(server_ip, user, password, cve_id, logger=None):
    try:
        if logger:
            logger.info(f"[{server_ip}] SSH 접속 시도")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server_ip, port=22, username=user, password=password, timeout=10)
        stdin, stdout, stderr = ssh.exec_command('ps -ef | egrep "apache|tomcat"')
        ps_result = stdout.read().decode("utf-8") + stderr.read().decode("utf-8")
        if logger:
            logger.info(f"[{server_ip}] ps 명령 결과 수신")
        cve_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        cve_res = requests.get(cve_url, timeout=8)
        if cve_res.status_code != 200:
            if logger:
                logger.warning(f"[{server_ip}] CVE API 실패: {cve_id}")
            return {"server": server_ip, "error": f"CVE 정보 조회 실패 ({cve_id})"}
        cve_json = cve_res.json()
        cve_json_str = json.dumps(cve_json, ensure_ascii=False, indent=2)
        if logger:
            logger.info(f"[{server_ip}] CVE JSON 수신")
        prompt1 = (
            "아래는 리눅스 웹서버의 프로세스 목록과 CVE 취약점 json입니다.\n"
            "1. 프로세스 목록을 보고 웹/서블릿 등 서버별 주요 설정파일 전체경로를 예상해.\n"
            "2. CVE json을 참고해서, 해당 취약점 진단에 실제 필요한 설정파일(경로)만 추려줘.\n"
            "최종적으로 반드시 실 경로만 쉼표(,)로 구분해서 한 줄로만 출력해줘.\n"
            "\n--- 프로세스 목록 ---\n"
            + ps_result +
            "\n--- CVE JSON ---\n"
            + cve_json_str
        )
        if logger:
            logger.info(f"\n수행 prompt: {prompt1[:1200]} \n...(생략)...")
        messages1 = [
            {"role": "system", "content": "당신은 리눅스 서버 및 보안 취약점 진단 전문가입니다."},
            {"role": "user", "content": prompt1}
        ]
        config_list_raw = ask_azure_openai(messages1, logger)
        if config_list_raw:
            config_paths = [x.strip() for x in config_list_raw.split(",") if x.strip().startswith("/")]
        else:
            config_paths = []
        if logger:
            logger.info(f"[{server_ip}] AI가 추출한 설정파일: {config_paths}")
        file_samples = {}
        for path in config_paths:
            try:
                sftp = ssh.open_sftp()
                with sftp.open(path) as f:
                    sample = f.read(2048).decode("utf-8", errors="ignore")
                    file_samples[path] = sample
                sftp.close()
            except Exception as fe:
                file_samples[path] = f"읽기 실패 또는 파일 없음 ({fe})"
        files_msg = "\n\n".join([f"--- {p} ---\n{file_samples[p][:8000]}" for p in file_samples])
        prompt2 = (
            f"아래는 CVE 취약점 json과 해당 서버의 주요 설정파일 내용입니다.\n"
            f"1. CVE json 내용을 먼저 정확하게 파악하고, 각 설정파일별로 실제 취약점이 존재하는지, 문제 부분은 어디인지 분석해줘.\n"
            f"2. 모든 파일을 종합해, 운영자에게 줄 수 있는 실무적인 취약점 진단 및 개선 권고 리포트 한글로 15줄 이내로 작성해줘.\n"
            f"3. 각 설정파일 별로 발견된 취약한 설정을 어떻게 변경하면 될지 차근차근하게 권고해줘.\n"
            f"\n--- CVE JSON ---\n{cve_json_str}\n\n--- 설정파일 내용들 ---\n{files_msg}"
        )
        if logger:
            logger.info(f"\n수행 prompt: {prompt2[:300]} \n...(생략)...")
        messages2 = [
            {"role": "system", "content": "당신은 보안 진단 전문가입니다."},
            {"role": "user", "content": prompt2}
        ]
        report = ask_azure_openai(messages2, logger)
        ssh.close()
        if logger:
            logger.info(f"[{server_ip}] 리포트 생성 완료")
        return {
            "server": server_ip,
            "config_paths": config_paths,
            "file_samples": file_samples,
            "report": report
        }
    except Exception as e:
        if logger:
            logger.error(f"[{server_ip}] 진단 과정 실패: {e}")
        return {"server": server_ip, "error": str(e)}
