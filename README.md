# 암호화 키 관리 시스템 (KMS)

이 프로젝트는 조직의 암호화 키를 안전하게 관리하기 위한 웹 기반 키 관리 시스템입니다.

## 주요 기능

- 암호화 키 생성 및 관리
- 키 버전 관리
- 사용자 인증 및 권한 관리
- 키 사용 감사 로그
- 안전한 키 백업 및 복구

## 설치 방법

1. Python 3.8 이상이 설치되어 있는지 확인합니다.

2. 가상환경을 생성하고 활성화합니다:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate  # Windows
```

3. 필요한 패키지를 설치합니다:
```bash
pip install -r requirements.txt
```

4. 환경 변수 파일을 설정합니다:
```bash
cp .env.example .env
# .env 파일을 편집하여 필요한 설정을 입력합니다.
```

5. 데이터베이스를 초기화합니다:
```bash
flask db upgrade
```

6. 애플리케이션을 실행합니다:
```bash
flask run
```

## 보안 주의사항

- 프로덕션 환경에서는 반드시 안전한 비밀키를 사용하세요.
- 데이터베이스 백업을 정기적으로 수행하세요.
- 모든 보안 업데이트를 즉시 적용하세요. 