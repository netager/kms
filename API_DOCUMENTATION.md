# KMS API 문서

## 기본 정보
- 기본 URL: `https://[서버 주소]/api/v1`
- 모든 요청에는 `X-API-Token` 헤더가 필요합니다.
- Content-Type: `application/json`

## 인증
모든 API 요청에는 유효한 API 토큰이 필요합니다.

**헤더 예시:**
```http
X-API-Token: your-api-token-here
```

## API 엔드포인트

### 1. 암호화 (Encryption)
텍스트를 암호화합니다.

- **URL:** `/encrypt`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
    "text": "암호화할 텍스트",
    "key_id": "사용할 키 ID",
    "program_name": "프로그램 이름"
  }
  ```
- **Response:**
  ```json
  {
    "encrypted_text": "암호화된 텍스트",
    "key_version": "사용된 키 버전"
  }
  ```
- **Error Response:**
  ```json
  {
    "error": "에러 메시지"
  }
  ```

### 2. 복호화 (Decryption)
암호화된 텍스트를 복호화합니다.

- **URL:** `/decrypt`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
    "encrypted_text": "암호화된 텍스트",
    "key_id": "사용할 키 ID",
    "program_name": "프로그램 이름"
  }
  ```
- **Response:**
  ```json
  {
    "decrypted_text": "복호화된 텍스트",
    "key_version": "사용된 키 버전"
  }
  ```
- **Error Response:**
  ```json
  {
    "error": "에러 메시지"
  }
  ```

### 3. 키 정보 조회
사용 가능한 키 정보를 조회합니다.

- **URL:** `/keys`
- **Method:** `GET`
- **Response:**
  ```json
  {
    "keys": [
      {
        "id": "키 ID",
        "name": "키 이름",
        "version": "키 버전",
        "created_at": "생성일시"
      }
    ]
  }
  ```

## 에러 코드
- 400: 잘못된 요청 (필수 파라미터 누락 등)
- 401: 인증 실패 (유효하지 않은 API 토큰)
- 403: 권한 없음
- 404: 리소스를 찾을 수 없음
- 500: 서버 내부 오류

## 주의사항
1. API 토큰은 안전하게 관리해야 합니다.
2. 프로덕션 환경에서는 반드시 HTTPS를 사용해야 합니다.
3. 암호화/복호화 요청 시 올바른 key_id를 사용해야 합니다.
4. program_name은 추적 및 감사를 위해 사용되므로 의미 있는 이름을 사용해야 합니다.

## 사용 예시

### cURL을 사용한 암호화 요청 예시:
```bash
curl -X POST "https://[서버 주소]/api/v1/encrypt" \
     -H "Content-Type: application/json" \
     -H "X-API-Token: your-api-token" \
     -d '{
       "text": "Hello, World!",
       "key_id": "1",
       "program_name": "test-app"
     }'
```

### Python 예시:
```python
import requests

url = "https://[서버 주소]/api/v1/encrypt"
headers = {
    "Content-Type": "application/json",
    "X-API-Token": "your-api-token"
}
data = {
    "text": "Hello, World!",
    "key_id": "1",
    "program_name": "test-app"
}

response = requests.post(url, headers=headers, json=data, verify=False)
result = response.json()
```

### Java 예시:
```java
OkHttpClient client = new OkHttpClient();
MediaType JSON = MediaType.parse("application/json; charset=utf-8");

JSONObject json = new JSONObject();
json.put("text", "Hello, World!");
json.put("key_id", "1");
json.put("program_name", "test-app");

Request request = new Request.Builder()
    .url("https://[서버 주소]/api/v1/encrypt")
    .addHeader("X-API-Token", "your-api-token")
    .post(RequestBody.create(JSON, json.toString()))
    .build();

Response response = client.newCall(request).execute();
```
```

이 문서는 API의 최신 스펙을 반영하고 있으며, 특히 다음 사항이 업데이트되었습니다:

1. 암호화/복호화 API의 파라미터 이름 수정 ('plaintext' → 'text')
2. 실제 사용 예시 추가
3. 에러 응답 형식 명확화
4. 주의사항 및 모범 사례 추가

이 문서를 통해 API 사용자들이 더 쉽게 통합 작업을 수행할 수 있을 것입니다. 