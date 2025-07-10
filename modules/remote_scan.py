import paramiko
from modules.azure_ai import ask_azure_openai

def ssh_and_find_files(server_ip, user, password, logger=None):
    result = {
        "server": server_ip,
        "process_output": "",
        "config_paths": [],
        "file_samples": {}
    }
    try:
        if logger:
            logger.info(f"[{server_ip}] SSH 연결 시도")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server_ip, port=22, username=user, password=password, timeout=8)
        stdin, stdout, stderr = ssh.exec_command('ps -ef | egrep "apache|tomcat"')
        process_output = stdout.read().decode("utf-8") + stderr.read().decode("utf-8")
        result["process_output"] = process_output
        if logger:
            logger.info(f"[{server_ip}] ps 결과 수신 및 AzureAI로 전송")
        prompt = (
            "아래는 ps -ef | egrep 'apache|tomcat' 명령 결과입니다. "
            "각 프로세스의 주요 설정파일(전체 경로) 리스트만 쉼표(,)로 구분해서 출력해줘. "
            "예: /etc/httpd/conf/httpd.conf,/usr/local/tomcat/conf/server.xml"
            "\n-----\n"
            + process_output
        )
        messages = [
            {"role": "system", "content": "당신은 리눅스 서버 엔지니어입니다."},
            {"role": "user", "content": prompt}
        ]
        config_list_raw = ask_azure_openai(messages, logger)
        if config_list_raw:
            config_paths = [x.strip() for x in config_list_raw.split(",") if x.strip().startswith("/")]
        else:
            config_paths = []
        result["config_paths"] = config_paths
        file_samples = {}
        for path in config_paths:
            try:
                sftp = ssh.open_sftp()
                with sftp.open(path) as f:
                    sample = f.read(512).decode("utf-8", errors="ignore")
                    file_samples[path] = sample
                sftp.close()
            except Exception as fe:
                file_samples[path] = f"읽기 실패 또는 파일 없음 ({fe})"
        result["file_samples"] = file_samples
        ssh.close()
        if logger:
            logger.info(f"[{server_ip}] 원격 진단 및 파일 샘플 수집 완료")
        return result
    except Exception as e:
        if logger:
            logger.error(f"[{server_ip}] 원격 진단 실패: {e}")
        return None
