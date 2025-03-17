# m2ee/decryptor.py
import requests
from typing import Optional

class JBKMSDecryptor:
    def __init__(self, config):
        """
        config: m2ee에서 이미 로드된 설정 객체
        """
        self.config = config
        self._setup_from_config()

    def _setup_from_config(self):
        """YAML에서 로드된 설정으로 초기화"""
        jbkms_config = self.config.get('jbkms', {})
        self.host_url = jbkms_config.get('HOST_URL')
        self.key_id = jbkms_config.get('KEY_ID')
        self.token = jbkms_config.get('TOKEN_KEY')
        self.prog_name = jbkms_config.get('PROG_NAME')
        # self.encrypted_values = jbkms_config.get('ENCRYPTED', {})

    def decrypt(self, value_name: str) -> Optional[str]:
        """
        ENCRYPTED 섹션에서 지정된 이름의 암호화된 값을 복호화
        
        :param value_name: ENCRYPTED 섹션의 키 이름
        :return: 복호화된 값 또는 None
        """
        # if value_name not in self.encrypted_values:
        #     return None

        encrypted_text = self.conf['mxruntime'][value_name]
        return self._call_decrypt_api(encrypted_text)

    def _call_decrypt_api(self, encrypted_text: str) -> Optional[str]:
        """app.py의 복호화 API 호출"""
        try:
            response = requests.post(
                f"{self.host_url}/api/v1/decrypt",
                headers={
                    'Content-Type': 'application/json',
                    'X-API-Token': self.token
                },
                json={
                    'encrypted_text': encrypted_text,
                    'key_id': self.key_id,
                    'prog_name': self.prog_name,
                },
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json().get('decrypted_text')
            return None
            
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return None