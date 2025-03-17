#!/usr/bin/env python3
import requests
import json

# KMS 서버 설정
KMS_SERVER = "http://localhost:5000"  # 실제 서버 주소로 변경 필요
API_TOKEN = "_JGT_fXhn57I0Onrvt7jFzGEsyjHiwA8wpukRKVxGJ4"     # 실제 API 토큰으로 변경 필요
PROGRAM_NAME = "API_Example"          # 프로그램명 설정

# 공통 헤더
headers = {
    "X-API-Token": API_TOKEN,
    "Content-Type": "application/json",
    "X-Program-Name": PROGRAM_NAME    # 프로그램명 추가
}

def encrypt_value(text, key_id):
    """값을 암호화합니다."""
    response = requests.post(
        f"{KMS_SERVER}/api/v1/encrypt",
        headers=headers,
        json={
            "text": text,
            "key_id": key_id
        }
    )
    
    if response.status_code == 200:
        return response.json()["encrypted_text"]
    else:
        raise Exception(f"암호화 실패: {response.json()['error']}")

def decrypt_value(encrypted_text, key_id):
    """암호화된 값을 복호화합니다."""
    response = requests.post(
        f"{KMS_SERVER}/api/v1/decrypt",
        headers=headers,
        json={
            "encrypted_text": encrypted_text,
            "key_id": key_id
        }
    )
    
    if response.status_code == 200:
        return response.json()["decrypted_text"]
    else:
        raise Exception(f"복호화 실패: {response.json()['error']}")

if __name__ == "__main__":
    # 테스트할 키 ID 설정
    KEY_ID = 1  # 실제 키 ID로 변경 필요
    
    try:
        # 암호화 테스트
        print("\n=== 암호화 테스트 ===")
        text_to_encrypt = "Hello, World!"
        print(f"원본 텍스트: {text_to_encrypt}")
        
        encrypted = encrypt_value(text_to_encrypt, KEY_ID)
        print(f"암호화된 텍스트: {encrypted}")
        
        # 복호화 테스트
        print("\n=== 복호화 테스트 ===")
        decrypted = decrypt_value(encrypted, KEY_ID)
        print(f"복호화된 텍스트: {decrypted}")
        
    except Exception as e:
        print(f"\n오류 발생: {str(e)}")