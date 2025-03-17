import requests
import yaml

# API 설정
BASE_URL = "http://127.0.0.1:8001"
API_TOKEN = "IcmyCGPoL42Ht0NAeAZs7lRoGAy1wKZwlTweFYdXWDM"
KEY_ID = 1
PROGRAM_NAME = "yaml_TestApp"
yaml_file_path = "/Users/netager/git_program/jb_kms26/test_prog/test_config_ecn.yaml"

# 헤더 설정
headers = {
    "X-API-Token": API_TOKEN,
    "Content-Type": "application/json"
}

with open(yaml_file_path, 'r', encoding='utf-8') as file:
    yaml_content = yaml.safe_load(file)

# 데이터베이스 섹션과 비밀번호 필드 확인
if 'database' not in yaml_content:
    raise ValueError('database 섹션이 없습니다.')
if 'password' not in yaml_content['database']:
    raise ValueError('database 섹션에 password 필드가 없습니다.')

# 암호화된 비밀번호 가져오기
encrypted_password = str(yaml_content['database']['password']).strip()

# 암호화된 텍스트 형식 확인
if not encrypted_password or not encrypted_password.startswith('gAAAAAB'):
    raise ValueError('유효하지 않은 암호화 텍스트입니다.')

# 복호화 API 호출
response = requests.post(
    f"{BASE_URL}/api/v1/decrypt",
    headers={
        'X-API-Token': API_TOKEN,
        'Content-Type': 'application/json'
    },
    json={
        'encrypted_text': encrypted_password,
        'key_id': KEY_ID,
        'program_name': PROGRAM_NAME
    }
)

# 응답 확인
if response.status_code == 200:
    result = response.json()
    if 'decrypted_text' not in result:
        raise ValueError('복호화 API 응답에 decrypted_text가 없습니다.')
    print(f"암호화된 텍스트: {encrypted_password}, 복호화된 텍스트: {result['decrypted_text']}")
else:
    error = response.json().get('error', '알 수 없는 오류')
    raise Exception(f'복호화 중 오류가 발생했습니다: {error}')