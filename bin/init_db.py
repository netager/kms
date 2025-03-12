from app import app, db
from app import User
import os

def init_db():
    # instance 디렉토리 생성
    if not os.path.exists('instance'):
        os.makedirs('instance')
    
    # 데이터베이스 테이블 생성
    with app.app_context():
        # 기존 테이블 삭제
        db.drop_all()
        
        # 새 테이블 생성
        db.create_all()
        
        # 관리자 계정 생성
        admin = User(
            username='kmsadmin',
            email='kmsadmin@example.com',
            is_admin=True
        )
        admin.set_password('tnscjs1%')  # 초기 비밀번호 설정
        
        db.session.add(admin)
        db.session.commit()
        
        print('데이터베이스가 초기화되었습니다.')
        print('관리자 계정이 생성되었습니다.')
        print('사용자명: admin')
        print('비밀번호: change_this_password')
        print('보안을 위해 즉시 비밀번호를 변경하세요.')

if __name__ == '__main__':
    init_db()