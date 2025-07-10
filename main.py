import streamlit as st
from modules.logger import setup_logger
from mcp import MCPContext
from modules.remote_audit import audit_server_with_cve
from modules.cve import get_cve_info_azure
from modules.remote_scan import ssh_and_find_files

logger = setup_logger()

def main():
    st.set_page_config(page_title="보안 취약점 진단 Agent", layout="wide")
    st.title("보안 취약점 진단 AI Agent")
    
    context = MCPContext()
    st.sidebar.header("기능 선택")

    menu = st.sidebar.radio("메뉴", ["CVE 조회", "원격 진단", "설정파일 취약점 진단", "조치 권고 리포트"])

    if menu == "CVE 조회":
        logger.info("CVE 조회 메뉴 진입")
        st.subheader("CVE 취약점 조회")
        cve_id = st.text_input("CVE ID를 입력하세요", value="CVE-2025-24813")
        if st.button("조회"):
            if not cve_id:
                st.warning("CVE ID를 입력하세요.")
                logger.warning("CVE ID 미입력")
            else:
                with st.spinner("Azure OpenAI로 CVE 정보 요약 중..."):
                    result = get_cve_info_azure(cve_id.strip(), logger)
                if result:
                    st.success("Azure OpenAI 요약 결과")
                    st.write(result)
                    logger.info(f"CVE 정보(AOAI) 요약 성공: {cve_id}")
                else:
                    st.error("정보를 가져오지 못했습니다.")
                    logger.warning(f"CVE 정보(AOAI) 조회 실패: {cve_id}")

    elif menu == "원격 진단":
        logger.info("원격 진단 메뉴 진입")
        st.subheader("서버 원격 진단")
        ip_input = st.text_input("서버 IP(여러 개 입력 시 콤마로 구분)", value="3.37.121.206, 3.39.54.49")
        user = st.text_input("계정", value="webwas")
        password = st.text_input("패스워드", value="Agsdev12~!", type="password")
        if st.button("진단 시작"):
            ips = [x.strip() for x in ip_input.split(",") if x.strip()]
            results = []
            for ip in ips:
                with st.spinner(f"{ip} 진단 중..."):
                    result = ssh_and_find_files(ip, user, password, logger)
                if result:
                    results.append(result)
                else:
                    st.error(f"{ip} 진단 실패 또는 연결 불가")
            for res in results:
                st.markdown(f"### 서버: {res['server']}")
                st.markdown("**프로세스 목록:**")
                st.code(res['process_output'])
                st.markdown("**AI가 추출한 설정파일 경로:**")
                if res["config_paths"]:
                    for path in res["config_paths"]:
                        st.write(f"- {path}")
                    st.markdown("**설정파일 내용 샘플(512바이트):**")
                    for path, content in res["file_samples"].items():
                        st.markdown(f"**{path}**")
                        st.code(content)
                else:
                    st.warning("설정파일 경로를 AI가 추출하지 못함")

    elif menu == "설정파일 취약점 진단":
        logger.info("설정파일 취약점 진단 메뉴 진입")
        st.subheader("설정파일 취약점 진단")
        ip_input = st.text_input("서버 IP(여러 개 입력 시 콤마로 구분)", value="3.37.121.206, 3.39.54.49")
        user = st.text_input("계정", value="webwas")
        password = st.text_input("패스워드", value="Agsdev12~!", type="password")
        cve_id = st.text_input("CVE ID", value="CVE-2025-24813")
        if st.button("진단 시작"):
            ips = [x.strip() for x in ip_input.split(",") if x.strip()]
            results = []
            for ip in ips:
                with st.spinner(f"{ip} 취약점 진단 중..."):
                    result = audit_server_with_cve(ip, user, password, cve_id, logger)
                results.append(result)
            for res in results:
                st.markdown(f"### 서버: {res.get('server', 'N/A')}")
                if "error" in res:
                    st.error(f"에러: {res['error']}")
                else:
                    st.markdown("**AI가 진단한 설정파일 목록:**")
                    for path in res["config_paths"]:
                        st.write(f"- {path}")
                    st.markdown("**진단 리포트:**")
                    st.info(res["report"] or "진단 리포트 없음")
                    st.markdown("<hr>", unsafe_allow_html=True)

    elif menu == "조치 권고 리포트":
        logger.info("조치 권고 리포트 메뉴 진입")
        st.info("조치 권고 리포트 (추후 구현 예정)")

if __name__ == "__main__":
    main()
