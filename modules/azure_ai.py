import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

AOAI_ENDPOINT = os.getenv("AOAI_ENDPOINT")
AOAI_API_KEY = os.getenv("AOAI_API_KEY")
AOAI_DEPLOY_GPT4O_MINI = os.getenv("AOAI_DEPLOY_GPT4O_MINI")
AOAI_API_VERSION = os.getenv("AOAI_API_VERSION")

def ask_azure_openai(messages, logger=None):
    url = f"{AOAI_ENDPOINT}/openai/deployments/{AOAI_DEPLOY_GPT4O_MINI}/chat/completions?api-version={AOAI_API_VERSION}"
    headers = {
        "Content-Type": "application/json",
        "api-key": AOAI_API_KEY,
    }
    data = {
        "messages": messages,
        "max_tokens": 1000,
        "temperature": 0.8,
        "top_p": 0.9,
        "stop": None
    }
    try:
        if logger:
            logger.info("Azure OpenAI API 호출")
        response = requests.post(url, headers=headers, json=data, timeout=25)
        response.raise_for_status()
        result = response.json()
        ai_reply = result["choices"][0]["message"]["content"]
        if logger:
            logger.info("Azure OpenAI 응답 수신 완료")
        return ai_reply
    except Exception as e:
        if logger:
            logger.error(f"Azure OpenAI 호출 중 오류: {e}")
        return None
