#!/bin/bash
cd ..

# 버전 정보 설정 (예: 1.0.0)
VERSION="1.0.0"
RELEASE_NAME="jbkms_${VERSION}"

# 임시 디렉토리 생성
TEMP_DIR="${RELEASE_NAME}"
mkdir -p ${TEMP_DIR}

# 필요한 파일들을 임시 디렉토리로 복사
echo "필요한 파일들을 복사합니다..."

# 애플리케이션 코어 파일
cp app.py config.py ${TEMP_DIR}/

# 템플릿 파일
cp -r templates ${TEMP_DIR}/

# 정적 파일
cp -r static ${TEMP_DIR}/

# 데이터베이스 마이그레이션
cp -r migrations ${TEMP_DIR}/

# 설정 파일
cp requirements.txt ${TEMP_DIR}/

# 실행 스크립트
mkdir -p ${TEMP_DIR}/bin
cp bin/* ${TEMP_DIR}/bin/

# 설치 스크립트
mkdir -p ${TEMP_DIR}/setup
cp setup/install_packages.sh ${TEMP_DIR}/setup/

#packages 디렉토리가 존재하면 복사
cp -r setup/packages ${TEMP_DIR}/setup/

# 로그 디렉토리 생성
mkdir -p ${TEMP_DIR}/logs

# README 파일 생성
cat > ${TEMP_DIR}/README.md << 'EOF'
# JB-KMS 설치 및 실행 가이드

## 1. 설치 방법

### 1.1 패키지 설치
```bash
# 패키지 설치 스크립트 실행
./setup/install_packages.sh
```

### 1.2 데이터베이스 초기화
```bash
# 가상환경 활성화
source venv/bin/activate

# 데이터베이스 초기화
flask db upgrade
python init_db.py

# 가상환경 비활성화
deactivate
```

### 1.3 환경 설정
.env 파일의 설정을 환경에 맞게 수정하세요:
- GUNICORN_PORT: 서버 포트 번호
- GUNICORN_WORKERS: 워커 프로세스 수 (CPU 코어 수 * 2 + 1 권장)
- GUNICORN_THREADS: 스레드 수 (2~4개 권장)
- GUNICORN_TIMEOUT: 타임아웃 설정

## 2. 서버 실행
```bash
# 서버 실행 스크립트 실행
./bin/start_server.sh
```

## 3. 로그 확인
- 접근 로그: logs/access.log
- 에러 로그: logs/error.log

## 4. 서버 중지
```bash
pkill -f gunicorn
```
EOF

# 압축 파일 생성
echo "압축 파일을 생성합니다..."
tar -czf "${RELEASE_NAME}.tar.gz" ${TEMP_DIR}

# 임시 디렉토리 삭제
rm -rf ${TEMP_DIR}

echo "배포 패키지가 생성되었습니다: ${RELEASE_NAME}.tar.gz" 
