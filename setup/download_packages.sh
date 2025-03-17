#!/bin/bash

# 다운로드 디렉토리 생성
DOWNLOAD_DIR="packages"
mkdir -p $DOWNLOAD_DIR

echo "패키지 다운로드를 시작합니다..."

# requirements.txt의 모든 패키지와 의존성 다운로드 (바이너리 제한 없이)
# 자신의 로컬 환경
# -----------------
# pip download \
#     --dest=$DOWNLOAD_DIR \
#     -r ../requirements.txt

# linux 환경
# ----------
pip download \
     -r ../requirements.txt \
     --platform manylinux2014_x86_64 \
     --only-binary=:all: \
     --python-version 3.9 \
     --dest=$DOWNLOAD_DIR

echo "다운로드가 완료되었습니다."
echo "다운로드된 파일은 '$DOWNLOAD_DIR' 디렉토리에 있습니다."


# 설치 스크립트 생성
cat > install_packages.sh << 'EOF'
#!/bin/bash

# 패키지 설치 디렉토리
PACKAGE_DIR="packages"

if [ ! -d "$PACKAGE_DIR" ]; then
    echo "에러: '$PACKAGE_DIR' 디렉토리를 찾을 수 없습니다."
    exit 1
fi

echo "필요한 시스템 패키지 설치 중..."
# Rocky Linux에 필요한 개발 도구 설치
#if command -v dnf &> /dev/null; then
#    sudo dnf groupinstall -y "Development Tools"
#    sudo dnf install -y python3-devel openssl-devel libffi-devel
#elif command -v yum &> /dev/null; then
#    sudo yum groupinstall -y "Development Tools"
#    sudo yum install -y python3-devel openssl-devel libffi-devel
#fi

echo "패키지 설치를 시작합니다..."

# 오프라인 모드로 패키지 설치
pip install \
    --no-index \
    --find-links=$PACKAGE_DIR \
    -r ../requirements.txt

echo "설치가 완료되었습니다."
EOF

# 설치 스크립트에 실행 권한 부여
chmod +x install_packages.sh

echo "설치 스크립트 'install_packages.sh'가 생성되었습니다."
echo "폐쇄망 환경에서는 'packages' 디렉토리와 'install_packages.sh'를 함께 이동하여 사용하세요." 
