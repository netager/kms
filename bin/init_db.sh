#!/bin/bash

# 파이썬 환경 설정
cd ..
#source venv/bin/activate


echo "데이터베이스 초기화를 시작합니다..."

# 1. 기존 데이터베이스 파일과 마이그레이션 폴더 삭제
echo "기존 데이터베이스 파일과 마이그레이션 폴더를 삭제합니다..."
rm -rf instance/* migrations/

# 2. 마이그레이션 초기화
echo "마이그레이션을 초기화합니다..."
flask db init

if [ $? -ne 0 ]; then
    echo "마이그레이션 초기화 중 오류가 발생했습니다."
    exit 1
fi

# 3. 초기 마이그레이션 생성
echo "초기 마이그레이션을 생성합니다..."
flask db migrate -m "initial migration"

if [ $? -ne 0 ]; then
    echo "마이그레이션 생성 중 오류가 발생했습니다."
    exit 1
fi

# 4. 마이그레이션 적용
echo "마이그레이션을 적용합니다..."
flask db upgrade

if [ $? -ne 0 ]; then
    echo "마이그레이션 적용 중 오류가 발생했습니다."
    exit 1
fi

echo "데이터베이스 초기화가 완료되었습니다!"

# 5. 관리자 계정 생성
# echo -e "\n관리자 계정을 생성합니다..."
# echo "관리자 사용자명을 입력하세요:"
# read admin_username

# # 이메일 입력 및 검증
# while true; do
#     echo "관리자 이메일을 입력하세요:"
#     read admin_email
#     if [[ $admin_email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
#         break
#     else
#         echo "올바른 이메일 형식이 아닙니다. 다시 입력해주세요."
#     fi
# done

# # 비밀번호 입력 및 검증
# while true; do
#     echo "비밀번호를 입력하세요 (최소 8자, 대문자, 소문자, 숫자, 특수문자 포함):"
#     read -s admin_password
#     echo
    
#     # 비밀번호 복잡도 검증
#     if [[ ${#admin_password} -lt 8 ]]; then
#         echo "비밀번호는 최소 8자 이상이어야 합니다."
#         continue
#     fi
#     if ! [[ $admin_password =~ [A-Z] ]]; then
#         echo "비밀번호에 대문자가 포함되어야 합니다."
#         continue
#     fi
#     if ! [[ $admin_password =~ [a-z] ]]; then
#         echo "비밀번호에 소문자가 포함되어야 합니다."
#         continue
#     fi
#     if ! [[ $admin_password =~ [0-9] ]]; then
#         echo "비밀번호에 숫자가 포함되어야 합니다."
#         continue
#     fi
#     if ! [[ $admin_password =~ ['!@#$%^&*()_+\-=\[\]{};:,.<>?'] ]]; then
#         echo "비밀번호에 특수문자가 포함되어야 합니다."
#         continue
#     fi

#     echo "비밀번호를 다시 입력하세요:"
#     read -s admin_password_confirm
#     echo
    
#     if [ "$admin_password" = "$admin_password_confirm" ]; then
#         break
#     else
#         echo "비밀번호가 일치하지 않습니다. 다시 입력해주세요."
#     fi
# done

# # Python 스크립트를 통해 관리자 생성
# python3 - << EOF
# from app import app, db, User
# with app.app_context():
#     # 기존 사용자가 있는지 확인
#     if User.query.first() is not None:
#         db.session.query(User).delete()
#         db.session.commit()
    
#     # 새 관리자 생성
#     admin = User(username='$admin_username', 
#                 email='$admin_email',
#                 is_admin=True)
#     admin.set_password('$admin_password')
#     db.session.add(admin)
#     db.session.commit()
#     print("관리자 계정이 성공적으로 생성되었습니다!")
# EOF

# if [ $? -ne 0 ]; then
#     echo "관리자 계정 생성 중 오류가 발생했습니다."
#     exit 1
# fi

# Python 스크립트를 통해 관리자 생성
python3 - << EOF
from app import app, db, User, get_current_time

with app.app_context():
    # 기존 사용자가 있는지 확인
    if User.query.first() is not None:
        db.session.query(User).delete()
        db.session.commit()
    
    # 새 관리자 생성
    admin = User(
        username='kmsadm', 
        email='kmsadm@jbbank.co.kr',
        is_admin=True,
        is_active=True,
        created_at=get_current_time()
    )
    admin.set_password('wjsqnr1%')
    db.session.add(admin)
    db.session.commit()
    print("관리자 계정이 성공적으로 생성되었습니다!")
EOF

if [ $? -ne 0 ]; then
    echo "관리자 계정 생성 중 오류가 발생했습니다."
    exit 1
fi

echo -e "\n초기화가 완료되었습니다!"
echo "관리자 계정으로 로그인할 수 있습니다:"
