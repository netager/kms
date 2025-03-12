#!/bin/bash

# 패키지 설치 디렉토리
PACKAGE_DIR="packages"

if [ ! -d "$PACKAGE_DIR" ]; then
    echo "에러: '$PACKAGE_DIR' 디렉토리를 찾을 수 없습니다."
    exit 1
fi

echo "필요한 시스템 패키지 설치 중..."
# Rocky Linux에 필요한 개발 도구 설치
if command -v dnf &> /dev/null; then
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y python3-devel openssl-devel libffi-devel
elif command -v yum &> /dev/null; then
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y python3-devel openssl-devel libffi-devel
fi

echo "패키지 설치를 시작합니다..."

# 오프라인 모드로 패키지 설치
pip install \
    --no-index \
    --find-links=$PACKAGE_DIR \
    -r requirements.txt

echo "설치가 완료되었습니다."
