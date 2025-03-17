from app import app, db, User
from werkzeug.security import generate_password_hash

def reset_admin_password():
    with app.app_context():
        # 관리자 계정 찾기
        admin = User.query.filter_by(is_admin=True).first()
        if admin:
            # 새 비밀번호 설정 (예: 'NewPassword123!')
            new_password = 'tnscjs1%'
            admin.password_hash = generate_password_hash(new_password)
            db.session.commit()
            print(f'관리자 {admin.username}의 비밀번호가 재설정되었습니다.')
        else:
            print('관리자 계정을 찾을 수 없습니다.')

if __name__ == '__main__':
    reset_admin_password()