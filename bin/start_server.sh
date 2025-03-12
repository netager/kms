#!/bin/bash

# 스크립트가 있는 디렉토리의 상위 디렉토리로 이동
#cd "$(dirname "$0")/.."
cd ..

# 환경 변수 로드

set -a
source .env
set +a

# 로그 디렉토리 생성
mkdir -p ${LOG_DIR}

# 가상환경 활성화
#source venv/bin/activate

# 서버 시작 메시지
echo "서버를 시작합니다..."
echo "포트: ${GUNICORN_PORT}"
echo "워커 수: ${GUNICORN_WORKERS}"
echo "스레드 수: ${GUNICORN_THREADS}"
echo "로그 위치: ${LOG_DIR}"

# Gunicorn 서버 실행
gunicorn \
    --workers ${GUNICORN_WORKERS} \
    --threads ${GUNICORN_THREADS} \
    --timeout ${GUNICORN_TIMEOUT} \
    --bind ${GUNICORN_BIND} \
    --access-logfile ${ACCESS_LOG} \
    --error-logfile ${ERROR_LOG} \
    --log-level info \
    --reload \
    "app:app"

# 주의: 이 부분은 실행되지 않습니다 (서버가 실행 중일 때)
