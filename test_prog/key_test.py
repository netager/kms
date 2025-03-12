import requests
import json
from datetime import datetime

class KmsKeyTest:
    def __init__(self, server_url, api_token):
        """KMS 키 테스트 클래스 초기화

        Args:
            server_url (str): KMS 서버 URL (예: http://localhost:8000)
            api_token (str): API 토큰
        """
        self.server_url = server_url.rstrip('/')
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Token': api_token
        }

    def request_key(self, key_id, program_name):
        """암호화 키 요청

        Args:
            key_id (int): 키 ID
            program_name (str): 프로그램 이름

        Returns:
            dict: 키 정보 (성공 시) 또는 None (실패 시)
        """
        url = f"{self.server_url}/api/v1/key"
        payload = {
            'key_id': key_id,
            'program_name': program_name
        }

        try:
            response = requests.post(url, 
                                  headers=self.headers,
                                  json=payload,
                                  verify=False)  # 개발 환경에서만 사용
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"오류 발생: {response.status_code}")
                print(response.json().get('error', '알 수 없는 오류'))
                return None

        except Exception as e:
            print(f"요청 중 오류 발생: {str(e)}")
            return None

    def print_key_info(self, key_info):
        """키 정보 출력

        Args:
            key_info (dict): 키 정보
        """
        if not key_info:
            print("키 정보가 없습니다.")
            return

        print("\n=== 키 정보 ===")
        print(f"키 ID: {key_info['request_info']['key_id']}")
        print(f"키 버전: {key_info['key_version']}")
        print(f"프로그램명: {key_info['request_info']['program_name']}")
        print(f"키 자료: {key_info['key_material'][:10]}...")  # 보안을 위해 일부만 출력
        print(f"Salt: {key_info['salt'][:10]}...")  # 보안을 위해 일부만 출력
        print("============")

def main():
    # 테스트 설정
    server_url = "http://localhost:8001"  # KMS 서버 URL
    api_token = "gPoCw3MAWYr-a4q9ESpZaQWZ-ALrIKG7sjbBqiiBMMQ"         # API 토큰
    key_id = 1                           # 테스트할 키 ID
    program_name = "KeyRequestTest"      # 프로그램명

    # 테스트 클래스 초기화
    tester = KmsKeyTest(server_url, api_token)

    # 키 요청 테스트
    print(f"키 요청 시작 - {datetime.now()}")
    print(f"서버 URL: {server_url}")
    print(f"키 ID: {key_id}")
    print(f"프로그램명: {program_name}")

    key_info = tester.request_key(key_id, program_name)
    
    if key_info:
        print("\n키 요청 성공!")
        tester.print_key_info(key_info)
    else:
        print("\n키 요청 실패!")

if __name__ == "__main__":
    main()