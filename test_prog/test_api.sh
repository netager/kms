#!/bin/bash

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# API 설정
# 서버 연결 테스트 및 URL 설정
echo -e "${YELLOW}서버 연결 테스트 중...${NC}"

if curl -s "http://127.0.0.1:8001" > /dev/null; then
    API_URL="http://localhost:8001"
    echo -e "${GREEN}서버 연결 성공: ${API_URL}${NC}"
else
    echo -e "${RED}Error: 서버에 연결할 수 없습니다. Flask 서버가 실행 중인지 확인하세요.${NC}"
    exit 1
fi

# API 설정값
API_TOKEN="IcmyCGPoL42Ht0NAeAZs7lRoGAy1wKZwlTweFYdXWDM"  # 실제 API 토큰으로 변경하세요
KEY_ID=1                       # 실제 키 ID로 변경하세요
PROGRAM_NAME="yaml_prog"
ENC_TEXT="전북1%"


# 암호화 테스트
echo -e "\n${YELLOW}=== 암호화 테스트 ===${NC}"
ENCRYPT_RESULT=$(curl -s -X POST "${API_URL}/api/v1/encrypt" \
  -H "X-API-Token: ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"text\": \"${ENC_TEXT}\",
    \"key_id\": ${KEY_ID},
    \"program_name\": \"${PROGRAM_NAME}\"
  }")

echo "----------------------"
echo $ENCRYPT_RESULT
echo "----------------------"

if echo "${ENCRYPT_RESULT}" | jq -e . >/dev/null 2>&1; then
    echo "${ENCRYPT_RESULT}" | jq '.'
    echo -e "${GREEN}암호화 성공${NC}"
    # 암호화된 텍스트 추출
    ENCRYPTED_TEXT=$(echo "${ENCRYPT_RESULT}" | jq -r '.encrypted_text')
else
    echo -e "${RED}암호화 실패: ${ENCRYPT_RESULT}${NC}"
    exit 1
fi

# 복호화 테스트
echo -e "\n${YELLOW}=== 복호화 테스트 ===${NC}"
DECRYPT_RESULT=$(curl -s -X POST "${API_URL}/api/v1/decrypt" \
  -H "X-API-Token: ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"encrypted_text\": \"${ENCRYPTED_TEXT}\",
    \"key_id\": ${KEY_ID},
    \"program_name\": \"${PROGRAM_NAME}\"
  }")

if echo "${DECRYPT_RESULT}" | jq -e . >/dev/null 2>&1; then
    echo "${DECRYPT_RESULT}" | jq '.'
    DECRYPTED_TEXT=$(echo "${DECRYPT_RESULT}" | jq -r '.decrypted_text')
    if [ "${DECRYPTED_TEXT}" == "${ENC_TEXT}" ]; then
        echo -e "${GREEN}복호화 성공 (원본 텍스트와 일치)${NC}"
    else
        echo -e "${RED}복호화된 텍스트가 원본과 다릅니다${NC}"
        exit 1
    fi
else
    echo -e "${RED}복호화 실패: ${DECRYPT_RESULT}${NC}"
    exit 1
fi

echo -e "\n${GREEN}모든 테스트가 성공적으로 완료되었습니다.${NC}" 
