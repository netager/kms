from flask import Flask, render_template, flash, redirect, url_for, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from datetime import datetime, timedelta
from config import Config

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
import secrets
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from functools import wraps
from markupsafe import Markup

import os
import yaml
import re
import requests
import pytz
import json
import logging
import traceback

# 로깅 설정
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# CSRF 보호 설정
csrf = CSRFProtect(app)

# 로그인 관리자 설정
login = LoginManager(app)
login.login_view = 'login'  # 로그인 뷰 함수명
login.login_message = ''
login.login_message_category = 'info'

# 에러 핸들러 추가
@app.errorhandler(403)
def forbidden_error(error):
    if not current_user.is_authenticated:
        return redirect(url_for('login', next=request.url))
    flash('이 페이지에 대한 접근 권한이 없습니다.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(401)
def unauthorized_error(error):
    return redirect(url_for('login', next=request.url))

# 한국 시간대 설정
KST = pytz.timezone('Asia/Seoul')

def get_current_time():
    """현재 한국 시간을 마이크로초 단위까지 반환합니다."""
    now = datetime.now(KST)
    return now.replace(microsecond=now.microsecond)

def get_client_ip():
    """클라이언트의 IP 주소를 반환합니다."""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# nl2br 필터 정의
@app.template_filter('nl2br')
def nl2br(value):
    if not value:
        return value
    return Markup(value.replace('\n', '<br>'))

# 폼 클래스 정의
class RegistrationForm(FlaskForm):
    username = StringField('로그인 ID', validators=[DataRequired()])
    username_kor = StringField('사용자명')
    email = EmailField('이메일', validators=[DataRequired(), Email()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    password2 = PasswordField('비밀번호 확인', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('가입하기')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('이미 사용 중인 로그인 ID입니다.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('이미 사용 중인 이메일입니다.')

# 키 관리 폼
class KeyForm(FlaskForm):
    name = StringField('키 이름', validators=[DataRequired()])
    description = TextAreaField('설명')
    submit = SubmitField('키 생성')

    def validate_name(self, name):
        key = Key.query.filter_by(name=name.data).first()
        if key is not None:
            raise ValidationError('이미 사용 중인 키 이름입니다.')

# 키 검색 폼
class KeySearchForm(FlaskForm):
    search_name = SelectField('암호키 이름', choices=[('', '전체')], default='')
    search_creator = SelectField('생성자', choices=[('', '전체')], default='')
    search_status = SelectField('상태', choices=[
        ('', '전체'),
        ('active', '활성'),
        ('inactive', '폐기')
    ], default='active')
    submit = SubmitField('검색')

# 암호화 테스트 폼
class EncryptionTestForm(FlaskForm):
    server_url = StringField('서버 URL', validators=[DataRequired()], default='http://localhost:8001')
    key_id = SelectField('암호키 선택', coerce=int, validators=[DataRequired()])
    api_token = SelectField('API 토큰', coerce=int, validators=[DataRequired()])
    program_name = StringField('프로그램명', validators=[DataRequired()])
    plaintext = TextAreaField('평문', validators=[DataRequired()])
    submit = SubmitField('암호화/복호화')

# YAML 복호화 테스트 폼
class YamlDecryptionTestForm(FlaskForm):
    server_url = StringField('서버 URL', validators=[DataRequired()], default='http://localhost:8001')
    key_id = SelectField('암호키 선택', coerce=int, validators=[DataRequired()])
    api_token = SelectField('API 토큰', coerce=int, validators=[DataRequired()])
    program_name = StringField('프로그램명', validators=[DataRequired()])
    yaml_file = FileField('YAML 파일', validators=[DataRequired()])
    submit = SubmitField('복호화')

# 로그인 폼
class LoginForm(FlaskForm):
    username = StringField('로그인 ID', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    submit = SubmitField('로그인')

# 로그 검색 폼 추가
class LogSearchForm(FlaskForm):
    start_date = StringField('시작일자', validators=[DataRequired()], default=lambda: get_current_time().strftime('%Y-%m-%d'))
    end_date = StringField('종료일자', validators=[DataRequired()], default=lambda: get_current_time().strftime('%Y-%m-%d'))
    key_id = SelectField('암호키', choices=[('', '전체')], default='', coerce=str)
    action = SelectField('작업 유형', choices=[
        ('', '전체'),
        ('encrypt', '암호화'),
        ('decrypt', '복호화'),
        ('get_key', '키조회')
    ], default='')
    program_name = StringField('프로그램명')
    status = SelectField('상태', choices=[
        ('', '전체'),
        ('success', '성공'),
        ('fail', '실패')
    ], default='')
    submit = SubmitField('검색')

# 사용자 관리 폼
class UserForm(FlaskForm):
    username = StringField('로그인 ID', validators=[DataRequired()])
    username_kor = StringField('사용자명')  # 한글 이름 필드 추가
    email = EmailField('이메일', validators=[DataRequired(), Email()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    is_admin = SelectField('권한', choices=[
        ('0', '일반 사용자'),
        ('1', '관리자')
    ], default='0')
    submit = SubmitField('사용자 추가')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('이미 사용 중인 사용자명입니다.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('이미 사용 중인 이메일입니다.')

# 사용자 검색 폼
class UserSearchForm(FlaskForm):
    search_username = StringField('사용자명')
    search_role = SelectField('권한', choices=[
        ('', '전체'),
        ('admin', '관리자'),
        ('user', '일반 사용자')
    ], default='')
    search_status = SelectField('상태', choices=[
        ('', '전체'),
        ('active', '활성'),
        ('inactive', '비활성')
    ], default='')
    submit = SubmitField('검색')

# 모델 정의
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    username_kor = db.Column(db.String(64), nullable=True)  # 한글 이름 필드 추가
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=get_current_time)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    key_material = db.Column(db.String(512), nullable=False)
    salt = db.Column(db.String(128), nullable=False)  # salt 저장 필드 추가
    version = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=get_current_time)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    active = db.Column(db.Boolean, default=True)
    deactivated_at = db.Column(db.DateTime, nullable=True)

class KeyAccessLog(db.Model):
    __tablename__ = 'key_access_log'
    
    access_time = db.Column(db.DateTime, default=get_current_time, primary_key=True)  # Primary Key의 일부
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'), primary_key=True)  # Primary Key의 일부
    action = db.Column(db.String(32))
    ip_address = db.Column(db.String(45))
    program_name = db.Column(db.String(100))
    is_success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500))
    token = db.Column(db.String(64))  # API 토큰 값 저장

# API 토큰 모델
class ApiToken(db.Model):
    __tablename__ = 'api_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    version = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # 관계 설정
    creator = db.relationship('User', backref=db.backref('api_tokens', lazy=True))

# API 토큰 히스토리 모델
class ApiTokenHistory(db.Model):
    __tablename__ = 'api_token_history'
    
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('api_tokens.id'), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    # old_value = db.Column(db.String(255))
    # new_value = db.Column(db.String(255))
    value = db.Column(db.String(255))
    # old_version = db.Column(db.Integer)
    # new_version = db.Column(db.Integer)
    version = db.Column(db.Integer)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    changed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # 관계 설정
    token = db.relationship('ApiToken', backref=db.backref('history', lazy=True))
    changed_by = db.relationship('User', backref=db.backref('token_changes', lazy=True))

# API 토큰 폼
class ApiTokenForm(FlaskForm):
    name = StringField('토큰명', validators=[DataRequired()])
    description = TextAreaField('토큰 설명')
    submit = SubmitField('토큰 생성')

# 키 히스토리 모델
class KeyHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'))
    key_material = db.Column(db.String(512), nullable=False)
    salt = db.Column(db.String(128), nullable=False)  # salt 저장 필드 추가
    version = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=get_current_time)
    rotated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# 사용자 접속 로그 모델 수정
class UserAccessLog(db.Model):
    __tablename__ = 'user_access_log'
    
    access_time = db.Column(db.DateTime, default=get_current_time, primary_key=True)
    username = db.Column(db.String(64), nullable=True)  # 로그인 시도한 사용자명 저장
    ip_address = db.Column(db.String(45))
    action = db.Column(db.String(20), nullable=False)  # 'login' 또는 'logout'
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500))
    is_registered_user = db.Column(db.Boolean, default=False)  # 등록된 사용자 여부
    
    def __init__(self, username=None, ip_address=None, action='login', success=True, error_message=None, is_registered_user=False):
        self.username = username
        self.ip_address = ip_address
        self.action = action
        self.success = success
        self.error_message = error_message
        self.is_registered_user = is_registered_user

def derive_key(key_material, salt=None):
    """키 자료로부터 암호화 키와 salt를 생성합니다."""
    if salt is None:
        # 새로운 salt 생성
        salt = secrets.token_bytes(16)
        salt_hex = base64.b64encode(salt).decode('utf-8')
    else:
        # 기존 salt 사용
        salt = base64.b64decode(salt.encode('utf-8'))
        salt_hex = base64.b64encode(salt).decode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
    return key, salt_hex

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# 관리자 권한 체크 데코레이터 추가
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('이 페이지는 관리자만 접근할 수 있습니다.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 라우트 정의
@app.route('/')
def root():
    return redirect(url_for('index'))

@app.route('/index')
def index():
    """메인 페이지를 표시합니다."""
    return render_template('index.html', title='홈')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            app.logger.info(f"로그인 시도: username={form.username.data}")
            user = User.query.filter_by(username=form.username.data).first()
            
            # 로그인 실패 처리 (잘못된 사용자명 또는 비밀번호)
            if user is None:
                app.logger.info(f"로그인 실패: 사용자가 존재하지 않음 (username={form.username.data})")
                # 로그인 실패 로그 기록
                access_log = UserAccessLog(
                    username=form.username.data,
                    ip_address=get_client_ip(),
                    action='login',
                    success=False,
                    error_message='사용자가 존재하지 않음',
                    is_registered_user=False
                )
                db.session.add(access_log)
                db.session.commit()
                flash('잘못된 사용자명 또는 비밀번호입니다.', 'error')
                return redirect(url_for('login'))
                
            if not user.check_password(form.password.data):
                app.logger.info(f"로그인 실패: 잘못된 비밀번호 (username={form.username.data})")
                # 로그인 실패 로그 기록
                access_log = UserAccessLog(
                    username=form.username.data,
                    ip_address=get_client_ip(),
                    action='login',
                    success=False,
                    error_message='잘못된 비밀번호',
                    is_registered_user=False
                )
                db.session.add(access_log)
                db.session.commit()
                flash('잘못된 사용자명 또는 비밀번호입니다.', 'error')
                return redirect(url_for('login'))
                
            # 비활성화된 계정 처리
            if not user.is_active:
                app.logger.info(f"로그인 실패: 비활성화된 계정 (username={form.username.data})")
                # 로그인 실패 로그 기록
                access_log = UserAccessLog(
                    username=form.username.data,
                    ip_address=get_client_ip(),
                    action='login',
                    success=False,
                    error_message='비활성화된 계정',
                    is_registered_user=False
                )
                db.session.add(access_log)
                db.session.commit()
                flash('비활성화된 계정입니다. 관리자에게 문의하세요.', 'error')
                return redirect(url_for('login'))
            
            # 로그인 성공 처리
            app.logger.info(f"로그인 성공: username={form.username.data}")
            login_user(user)
            current_time = get_current_time()
            user.last_login = current_time
            
            try:
                # 로그인 성공 로그 기록
                access_log = UserAccessLog(
                    username=user.username,
                    ip_address=get_client_ip(),
                    action='login',
                    success=True,
                    is_registered_user=True
                )
                db.session.add(access_log)
                db.session.add(user)
                db.session.commit()
                app.logger.info(f"마지막 로그인 시간 업데이트 성공: username={user.username}")
            except Exception as e:
                app.logger.error(f"마지막 로그인 시간 업데이트 실패: {str(e)}")
                db.session.rollback()
            
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('index')
            return redirect(next_page)
            
        except Exception as e:
            app.logger.error(f"로그인 처리 중 오류 발생: {str(e)}\n{traceback.format_exc()}")
            db.session.rollback()
            flash('로그인 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html', title='로그인', form=form)

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        username = current_user.username
        # 로그아웃 로그 기록
        access_log = UserAccessLog(
            username=username,
            ip_address=get_client_ip(),
            action='logout',
            success=True,
            is_registered_user=True
        )
        db.session.add(access_log)
        db.session.commit()
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            username_kor=form.username_kor.data,
            email=form.email.data,
            is_admin=False,  # 기본값으로 False 설정
            is_active=True,
            created_at=get_current_time()  # 명시적으로 created_at 설정
        )
        user.set_password(form.password.data)
        # 첫 번째 사용자를 관리자로 설정
        if User.query.count() == 0:
            user.is_admin = True
        db.session.add(user)
        db.session.commit()
        flash('회원가입이 완료되었습니다. 로그인해주세요.')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# 키 관리 라우트
@app.route('/keys', methods=['GET', 'POST'])
@login_required
@admin_required
def keys():
    """암호키 관리 페이지를 표시합니다."""
    search_form = KeySearchForm()
    form = KeyForm()

    # 검색 조건 처리
    search_name = request.args.get('search_name', '')
    search_creator = request.args.get('search_creator', '')
    search_status = request.args.get('search_status', 'active')

    # 암호키 이름 옵션 설정
    keys = Key.query.with_entities(Key.name).distinct().all()
    search_form.search_name.choices = [('', '전체')] + [(k.name, k.name) for k in keys]

    # 생성자 옵션 설정
    creators = User.query.join(Key, User.id == Key.created_by_id).distinct().all()
    search_form.search_creator.choices = [('', '전체')] + [(u.username, u.username) for u in creators]

    # 검색 폼의 선택된 값 유지
    search_form.search_name.data = search_name
    search_form.search_creator.data = search_creator
    search_form.search_status.data = search_status

    # 기본 쿼리 생성
    query = db.session.query(Key, User.username).join(
        User, Key.created_by_id == User.id
    )

    # 검색 조건 적용
    if search_name:
        query = query.filter(Key.name == search_name)
    if search_creator:
        query = query.filter(User.username == search_creator)
    if search_status:
        is_active = (search_status == 'active')
        query = query.filter(Key.active == is_active)

    # 결과 조회
    keys = query.all()
    
    return render_template('keys.html', 
                         keys=keys, 
                         form=form, 
                         search_form=search_form,
                         search_name=search_name,
                         search_creator=search_creator,
                         search_status=search_status)

@app.route('/key/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_key():
    """새로운 암호키를 생성합니다."""
    form = KeyForm()
    result = {
        'success': False,
        'message': '',
        'key_info': None
    }

    if form.validate_on_submit():
        try:
            key_material = secrets.token_hex(32)
            derived_key, salt_hex = derive_key(key_material)
            
            key = Key(
                name=form.name.data,
                description=form.description.data,
                key_material=key_material,
                salt=salt_hex,
                created_by_id=current_user.id
            )
            db.session.add(key)
            db.session.flush()
            
            key_history = KeyHistory(
                key_id=key.id,
                key_material=key_material,
                salt=salt_hex,
                version=1,
                action='create',
                created_at=get_current_time(),
                rotated_by_id=current_user.id
            )
            db.session.add(key_history)
            db.session.commit()

            result['success'] = True
            result['message'] = '새로운 키가 성공적으로 생성되었습니다.'
            result['key_info'] = {
                'id': key.id,
                'name': key.name,
                'created_at': get_current_time().strftime('%Y-%m-%d %H:%M:%S')
            }

        except Exception as e:
            db.session.rollback()
            result['success'] = False
            result['message'] = f'키 생성 중 오류가 발생했습니다: {str(e)}'
            app.logger.error(f"키 생성 오류: {str(e)}")

    return jsonify(result)

@app.route('/key/created')
@login_required
def key_created():
    # 세션에서 새로 생성된 키 정보 가져오기
    new_key = session.pop('new_key', None)
    if not new_key:
        return redirect(url_for('keys'))
    
    return render_template('key_created.html', key=new_key)

@app.route('/key/<int:key_id>/rotate', methods=['POST'])
@login_required
@admin_required
def rotate_key(key_id):
    """암호키를 교체합니다."""
    result = {
        'success': False,
        'message': '',
        'key_info': None
    }

    try:
        key = Key.query.get_or_404(key_id)
        
        # 새로운 키와 salt 생성
        new_key_material = secrets.token_hex(32)
        derived_key, new_salt_hex = derive_key(new_key_material)
        
        # 이전 키 정보 저장
        old_key_material = key.key_material
        old_salt = key.salt
        old_version = key.version
        
        # 원장(Key 테이블) 업데이트
        key.key_material = new_key_material
        key.salt = new_salt_hex
        key.version += 1
        key.created_at = get_current_time()
        db.session.flush()  # 변경사항을 DB에 반영하되 커밋은 하지 않음
        
        # 히스토리에 새로운 키 정보 저장
        key_history = KeyHistory(
            key_id=key.id,
            key_material=new_key_material,
            salt=new_salt_hex,
            version=key.version,
            action='rotate',
            created_at=get_current_time(),
            rotated_by_id=current_user.id
        )
        db.session.add(key_history)
        
        db.session.commit()

        result['success'] = True
        result['message'] = '키가 성공적으로 변경되었습니다.'
        result['key_info'] = {
            'id': key.id,
            'name': key.name,
            'old_version': old_version,
            'new_version': key.version,
            'updated_at': get_current_time().strftime('%Y-%m-%d %H:%M:%S')
        }

    except Exception as e:
        db.session.rollback()
        result['success'] = False
        result['message'] = f'키 변경 중 오류가 발생했습니다: {str(e)}'
        app.logger.error(f"키 변경 오류: {str(e)}")

    return jsonify(result)

@app.route('/key/<int:key_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_key(key_id):
    """암호키를 폐기합니다."""
    result = {
        'success': False,
        'message': '',
        'key_info': None
    }

    try:
        key = Key.query.get_or_404(key_id)
        if not key.active:
            result['message'] = '이미 폐기된 키입니다.'
            return jsonify(result)
        
        current_time = get_current_time()
        
        # 키 폐기 히스토리 기록
        key_history = KeyHistory(
            key_id=key.id,
            key_material=key.key_material,
            salt=key.salt,
            version=key.version,
            action='deactivate',
            created_at=current_time,
            rotated_by_id=current_user.id
        )
        db.session.add(key_history)
        
        # 키 폐기
        key.active = False
        key.deactivated_at = current_time
        db.session.commit()
        
        result['success'] = True
        result['message'] = '키가 폐기되었습니다.'
        result['key_info'] = {
            'id': key.id,
            'name': key.name,
            'version': key.version,
            'deactivated_at': current_time.strftime('%Y-%m-%d %H:%M:%S')
        }

    except Exception as e:
        db.session.rollback()
        result['success'] = False
        result['message'] = f'키 폐기 중 오류가 발생했습니다: {str(e)}'
        app.logger.error(f"키 폐기 오류: {str(e)}")

    return jsonify(result)

@app.route('/key/<int:key_id>/history')
@login_required
def key_history(key_id):
    """암호키의 변경 내역을 조회합니다."""
    # 키 존재 여부 확인
    key = Key.query.get_or_404(key_id)
    
    # 키 히스토리 조회 - 사용자 ID 체크 제거
    histories = db.session.query(KeyHistory, User.username)\
        .join(User, KeyHistory.rotated_by_id == User.id)\
        .filter(KeyHistory.key_id == key_id)\
        .order_by(KeyHistory.created_at.desc())\
        .all()
    
    # 키 생성자 정보 조회
    creator = User.query.get(key.created_by_id)
    
    return render_template('key_history.html', 
                         key=key, 
                         histories=histories,
                         creator=creator.username if creator else '알 수 없음')

@app.route('/key/<int:key_id>/detail')
@login_required
@admin_required
def key_detail(key_id):
    """암호키의 상세 정보를 조회합니다."""
    key = Key.query.get_or_404(key_id)
    creator = User.query.get(key.created_by_id)
    
    return render_template('key_detail.html', 
                         key=key,
                         creator=creator.username if creator else '알 수 없음',
                         salt=key.salt,
                         deactivated_at=key.deactivated_at.strftime('%Y-%m-%d %H:%M:%S') if key.deactivated_at else None)

@app.route('/text_encryption_test', methods=['GET', 'POST'])
@login_required
def text_encryption_test():
    # 사용 가능한 키 목록 가져오기
    keys = Key.query.filter_by(active=True).all()
    form = EncryptionTestForm()
    form.key_id.choices = [(key.id, key.name) for key in keys]

    # 사용 가능한 API 토큰 목록 가져오기
    tokens = ApiToken.query.filter_by(creator_id=current_user.id, is_active=True).all()
    form.api_token.choices = [(token.id, token.description) for token in tokens]

    result = {
        'success': False,
        'message': '',
        'encrypted_text': None,
        'decrypted_text': None,
        'key_version': None,
        'encryption_success': False,
        'decryption_success': False
    }

    if form.validate_on_submit():
        try:
            key = Key.query.get(form.key_id.data)
            token = ApiToken.query.get(form.api_token.data)
            
            if not key or not token:
                result['message'] = '유효하지 않은 키 또는 API 토큰입니다.'
                return render_template('text_encryption_test.html', form=form, result=result)

            # 암호화 API 호출
            encrypt_url = f"{form.server_url.data}/api/v1/encrypt"
            headers = {
                'Content-Type': 'application/json',
                'X-API-Token': token.token
            }
            encrypt_payload = {
                'text': form.plaintext.data,
                'key_id': key.id,
                'program_name': form.program_name.data
            }
            
            app.logger.debug(f"Encryption payload: {encrypt_payload}")  # 디버깅을 위한 로그 추가
            
            encrypt_response = requests.post(
                encrypt_url,
                headers=headers,
                json=encrypt_payload,
                verify=False
            )
            
            if encrypt_response.status_code != 200:
                error_data = encrypt_response.json()
                result['message'] = f'암호화 실패: {error_data.get("error", "알 수 없는 오류")}'
                app.logger.error(f"Encryption failed: {error_data}")  # 디버깅을 위한 로그 추가
                return render_template('text_encryption_test.html', 
                                    form=form,
                                    result=result)
            
            encrypted_data = encrypt_response.json()
            result['encrypted_text'] = encrypted_data['encrypted_text']
            result['key_version'] = encrypted_data.get('key_version')
            result['encryption_success'] = True

            # 복호화 API 호출
            decrypt_url = f"{form.server_url.data}/api/v1/decrypt"
            decrypt_payload = {
                'encrypted_text': result['encrypted_text'],
                'key_id': key.id,
                'program_name': form.program_name.data
            }
            
            decrypt_response = requests.post(
                decrypt_url,
                headers=headers,
                json=decrypt_payload,
                verify=False
            )
            
            if decrypt_response.status_code != 200:
                error_data = decrypt_response.json()
                result['message'] = f'복호화 실패: {error_data.get("error", "알 수 없는 오류")}'
                return render_template('text_encryption_test.html', 
                                    form=form,
                                    result=result)
            
            decrypted_data = decrypt_response.json()
            result['decrypted_text'] = decrypted_data['decrypted_text']
            result['decryption_success'] = True

            # 전체 프로세스 성공 여부 확인
            if result['encryption_success'] and result['decryption_success']:
                result['success'] = True
                if form.plaintext.data == result['decrypted_text']:
                    result['message'] = '암호화/복호화가 성공적으로 완료되었습니다.'
                else:
                    result['message'] = '암호화/복호화는 성공했으나, 원본 텍스트와 복호화된 텍스트가 일치하지 않습니다.'
                    result['success'] = False

        except Exception as e:
            app.logger.error(f"암호화/복호화 중 오류 발생: {str(e)}")
            result['message'] = f'처리 중 오류가 발생했습니다: {str(e)}'
            
    return render_template('text_encryption_test.html', form=form, result=result)

@app.route('/yaml_decryption_test', methods=['GET', 'POST'])
@login_required
def yaml_decryption_test():
    # 사용 가능한 키 목록 가져오기
    keys = Key.query.filter_by(active=True).all()
    form = YamlDecryptionTestForm()
    form.key_id.choices = [(key.id, key.name) for key in keys]
    
    # 사용 가능한 API 토큰 목록 가져오기
    tokens = ApiToken.query.filter_by(creator_id=current_user.id, is_active=True).all()
    form.api_token.choices = [(token.id, token.description) for token in tokens]

    result = {
        'yaml_result': None,
        'original_yaml': None,
        'success': False,
        'message': '',
        'key_version': None
    }

    if form.validate_on_submit():
        if not form.yaml_file.data:
            flash('YAML 파일을 선택해주세요.', 'error')
            return render_template('yaml_decryption_test.html', form=form)
            
        yaml_file = form.yaml_file.data
        # 파일 내용을 문자열로 읽기
        file_content = yaml_file.read().decode('utf-8')
        result['original_yaml'] = file_content
        
        try:
            # YAML 파일 내용 읽기
            yaml_content = yaml.safe_load(file_content)
            
            if not isinstance(yaml_content, dict):
                result['success'] = False
                result['message'] = '유효하지 않은 YAML 형식입니다.'
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)
                                    
            # 선택된 키와 API 토큰 가져오기
            key = Key.query.get(form.key_id.data)
            token = ApiToken.query.get(form.api_token.data)
            
            if not key or not token:
                result['success'] = False
                result['message'] = '유효하지 않은 키 또는 API 토큰입니다.'
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)
                                    
            # database 섹션 확인
            if 'database' not in yaml_content:
                result['success'] = False
                result['message'] = 'database 섹션이 없습니다.'
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)
                
            if 'password' not in yaml_content['database']:
                result['success'] = False
                result['message'] = 'database 섹션에 password 필드가 없습니다.'
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)

            # 암호화된 값 복호화
            password = str(yaml_content['database']['password']).strip()
            app.logger.info(f"파일에서 읽은 password 값: {password}")
            
            if not password or not isinstance(password, str) or not password.startswith('gAAAAAB'):
                result['success'] = False
                result['message'] = 'password 필드가 평문이거나 유효하지 않은 암호화 텍스트입니다.'
                result['yaml_result'] = file_content
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)

            try:
                # 복호화 API 호출
                decrypt_url = f"{form.server_url.data}/api/v1/decrypt"
                headers = {
                    'Content-Type': 'application/json',
                    'X-API-Token': token.token
                }
                decrypt_payload = {
                    'encrypted_text': password,
                    'key_id': key.id,
                    'program_name': form.program_name.data
                }
                
                decrypt_response = requests.post(
                    decrypt_url,
                    headers=headers,
                    json=decrypt_payload,
                    verify=False  # 개발 환경에서만 사용
                )
                
                if decrypt_response.status_code != 200:
                    error_data = decrypt_response.json()
                    result['success'] = False
                    result['message'] = error_data.get('error', '복호화 중 오류가 발생했습니다.')
                    return render_template('yaml_decryption_test.html', 
                                        form=form,
                                        result=result)
                
                decrypted_data = decrypt_response.json()
                result['success'] = True
                result['message'] = '복호화가 성공적으로 완료되었습니다.'
                result['key_version'] = decrypted_data.get('key_version')
                
                # 기존 결과 형식 유지
                yaml_result = {
                    'encrypted_password': password,
                    'decrypted_password': decrypted_data['decrypted_text'],
                    'key_version': decrypted_data.get('key_version')
                }
                result['yaml_result'] = yaml.dump(yaml_result, allow_unicode=True, default_flow_style=False)
                
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)
                                    
            except Exception as e:
                result['success'] = False
                result['message'] = f'복호화 중 오류가 발생했습니다: {str(e)}'
                app.logger.error(f"복호화 중 오류: {e}")
                return render_template('yaml_decryption_test.html', 
                                    form=form,
                                    result=result)
                                    
        except yaml.YAMLError as e:
            result['success'] = False
            result['message'] = f'YAML 파일 파싱 중 오류가 발생했습니다: {str(e)}'
            return render_template('yaml_decryption_test.html', 
                                form=form,
                                result=result)
            
    return render_template('yaml_decryption_test.html', form=form)

def require_api_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        data = request.get_json() or {}
        key_id = data.get('key_id')
        program_name = data.get('program_name', 'Unknown')

        if not token:
            # 토큰 누락 로그
            log = KeyAccessLog(
                key_id=key_id,
                access_time=get_current_time(),
                action=request.endpoint.replace('api_', ''),  # api_encrypt -> encrypt
                ip_address=get_client_ip(),
                program_name=program_name,
                is_success=False,
                error_message='API 토큰이 필요합니다.',
                token=token
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({'error': 'API 토큰이 필요합니다.'}), 401
        
        api_token = ApiToken.query.filter_by(token=token, is_active=True).first()
        if not api_token:
            # 유효하지 않은 토큰 로그
            log = KeyAccessLog(
                key_id=key_id,
                access_time=get_current_time(),
                action=request.endpoint.replace('api_', ''),  # api_encrypt -> encrypt
                ip_address=get_client_ip(),
                program_name=program_name,
                is_success=False,
                error_message='유효하지 않은 토큰입니다.',
                token=token
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({'error': '유효하지 않은 토큰입니다.'}), 401
        
        # 마지막 사용 시간 업데이트
        api_token.last_used_at = get_current_time()
        db.session.commit()
        
        # 요청에 사용자 정보 추가
        request.user = User.query.get(api_token.creator_id)
        return f(*args, **kwargs)
    return decorated

# API 토큰 관리 라우트
@app.route('/manage_tokens', methods=['GET', 'POST'])
@login_required
def manage_tokens():
    form = ApiTokenForm()
    
    if request.method == 'GET':
        # 검색 조건 가져오기
        search_name = request.args.get('search_name', '')
        search_status = request.args.get('search_status', '')
        search_creator = request.args.get('search_creator', '')
        
        # 토큰 쿼리 생성
        query = ApiToken.query
        
        if search_name:
            query = query.filter(ApiToken.name == search_name)
        if search_status:
            query = query.filter(ApiToken.is_active == (search_status == 'active'))
        if search_creator:
            query = query.filter(ApiToken.creator_id == int(search_creator))
            
        tokens = query.all()
        token_names = db.session.query(ApiToken.name).distinct().all()
        token_names = [name[0] for name in token_names]
        
        # 생성자 목록 가져오기
        creators = User.query.all()
        
        return render_template('api_tokens.html', 
                             tokens=tokens, 
                             token_names=token_names,
                             creators=creators,
                             form=form)

    if request.method == 'POST':
        if not request.is_json:
            return jsonify({'success': False, 'error': '잘못된 요청 형식입니다.'}), 400
            
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        
        if not name:
            return jsonify({'success': False, 'error': '토큰 이름은 필수입니다.'}), 400
            
        try:
            current_time = get_current_time()
            token_value = secrets.token_urlsafe(32)
            
            # 토큰 생성
            api_token = ApiToken(
                token=token_value,
                name=name,
                description=description,
                creator_id=current_user.id,
                version=1,
                created_at=current_time
            )
            db.session.add(api_token)
            db.session.flush()  # ID 생성을 위해 flush
            
            # 토큰 생성 히스토리 기록
            history = ApiTokenHistory(
                token_id=api_token.id,
                action='create',
                value=token_value,
                version=1,
                changed_at=current_time,
                changed_by_id=current_user.id
            )
            db.session.add(history)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': '토큰이 성공적으로 생성되었습니다.',
                'token': {
                    'id': api_token.id,
                    'name': api_token.name,
                    'value': token_value,
                    'version': api_token.version,
                    'created_at': current_time.strftime('%Y-%m-%d %H:%M:%S')
                }
            })
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"토큰 생성 중 오류 발생: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'토큰 생성 중 오류가 발생했습니다: {str(e)}'
            }), 500

@app.route('/token/<int:token_id>/deactivate', methods=['POST'])
@login_required
def deactivate_token(token_id):
    """API 토큰을 비활성화합니다."""
    try:
        token = ApiToken.query.get_or_404(token_id)
        
        # 권한 확인
        if not current_user.is_admin and token.creator_id != current_user.id:
            return jsonify({'success': False, 'message': '권한이 없습니다.'}), 403
        
        current_time = get_current_time()
        
        # 토큰 비활성화
        token.is_active = False
        
        # 토큰 폐기 히스토리 기록
        history = ApiTokenHistory(
            token_id=token.id,
            action='deactivate',
            value=token.token,
            version=token.version,
            changed_at=current_time,
            changed_by_id=current_user.id
        )
        db.session.add(history)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'API 토큰이 성공적으로 폐기되었습니다.'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"토큰 폐기 중 오류 발생: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'토큰 폐기 중 오류가 발생했습니다: {str(e)}'
        }), 500

@app.route('/token/<int:token_id>/rotate', methods=['POST'])
@login_required
def rotate_token(token_id):
    """API 토큰을 교체합니다."""
    try:
        token = ApiToken.query.get_or_404(token_id)
        
        # 토큰 소유자 또는 관리자만 접근 가능
        if token.creator_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': '권한이 없습니다.'}), 403
        
        current_time = get_current_time()
        
        # 이전 토큰 정보 저장
        old_version = token.version
        
        # 새로운 토큰 생성
        new_token_value = secrets.token_urlsafe(32)
        
        # 토큰 업데이트
        token.token = new_token_value
        token.version += 1
        token.last_used_at = current_time
        
        # 토큰 변경 히스토리 기록 - 새로운 토큰만 저장
        history = ApiTokenHistory(
            token_id=token.id,
            action='rotate',
            value=new_token_value,
            version=token.version,
            changed_at=current_time,
            changed_by_id=current_user.id
        )
        db.session.add(history)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '토큰이 성공적으로 변경되었습니다.',
            'token_info': {
                'id': token.id,
                'name': token.name,
                'new_token': new_token_value,
                'old_version': old_version,
                'new_version': token.version,
                'updated_at': current_time.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"토큰 변경 오류: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'토큰 변경 중 오류가 발생했습니다: {str(e)}'
        }), 500

@app.route('/token/<int:token_id>/history')
@login_required
def token_history(token_id):
    """API 토큰의 변경 내역을 조회합니다."""
    try:
        # 토큰 존재 여부 확인
        token = ApiToken.query.get_or_404(token_id)
        
        # 토큰 소유자 또는 관리자만 접근 가능
        if token.creator_id != current_user.id and not current_user.is_admin:
            flash('권한이 없습니다.', 'error')
            return redirect(url_for('manage_tokens'))
        
        # 토큰 히스토리 조회
        histories = db.session.query(ApiTokenHistory, User.username)\
            .outerjoin(User, ApiTokenHistory.changed_by_id == User.id)\
            .filter(ApiTokenHistory.token_id == token_id)\
            .order_by(ApiTokenHistory.changed_at.desc())\
            .all()
        
        return render_template('token_history.html', 
                             token=token,
                             histories=histories)
    except Exception as e:
        app.logger.error(f"토큰 히스토리 조회 중 오류 발생: {str(e)}")
        flash('토큰 히스토리를 조회하는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('manage_tokens'))

@app.route('/api/token_history/<int:history_id>')
@login_required
def get_token_history_detail(history_id):
    """토큰 히스토리 상세 정보를 조회합니다."""
    try:
        # 히스토리 조회
        history = ApiTokenHistory.query.get_or_404(history_id)
        
        # 해당 토큰에 대한 접근 권한 확인
        token = ApiToken.query.get(history.token_id)
        if not token or (token.creator_id != current_user.id and not current_user.is_admin):
            return jsonify({'success': False, 'error': '권한이 없습니다.'}), 403
        
        # 변경을 수행한 사용자 정보 조회
        changed_by = User.query.get(history.changed_by_id)
        
        action_text = {
            'create': '토큰 생성',
            'rotate': '토큰 변경',
            'deactivate': '토큰 폐기'
        }.get(history.action, history.action)
        
        return jsonify({
            'success': True,
            'history_detail': {
                'token_id': history.token_id,
                'value': history.value,
                'version': history.version if history.version else '-',
                'action': action_text,
                'changed_at': history.changed_at.strftime('%Y-%m-%d %H:%M:%S'),
                'changed_by': changed_by.username if changed_by else '알 수 없음'
            }
        })
    except Exception as e:
        app.logger.error(f"토큰 히스토리 상세 조회 중 오류 발생: {str(e)}")
        return jsonify({
            'success': False,
            'error': '토큰 히스토리 상세 정보를 조회하는 중 오류가 발생했습니다.'
        }), 500

@app.route('/api/key_history/<int:history_id>')
@login_required
def get_key_history_detail(history_id):
    """키 히스토리 상세 정보를 조회합니다."""
    try:
        # 히스토리 조회
        history = KeyHistory.query.get_or_404(history_id)
        
        # 해당 키에 대한 접근 권한 확인
        key = Key.query.get(history.key_id)
        if not key or not current_user.is_admin:
            return jsonify({'success': False, 'error': '권한이 없습니다.'}), 403
        
        # 변경을 수행한 사용자 정보 조회
        rotated_by = User.query.get(history.rotated_by_id)
        
        action_text = {
            'create': '생성',
            'rotate': '변경',
            'deactivate': '폐기'
        }.get(history.action, history.action)
        
        return jsonify({
            'success': True,
            'history_detail': {
                'key_id': history.key_id,
                'version': history.version,
                'action': action_text,
                'key_material': history.key_material[:10] + '****************',
                'salt': history.salt[:10] + '****************',
                'rotated_by': rotated_by.username if rotated_by else '알 수 없음',
                'created_at': history.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        app.logger.error(f"키 히스토리 상세 조회 중 오류 발생: {str(e)}")
        return jsonify({
            'success': False,
            'error': '키 히스토리 상세 정보를 조회하는 중 오류가 발생했습니다.'
        }), 500

@app.route('/user_access_history')
@login_required
@admin_required
def user_access_history():
    """사용자 접속 내역 페이지를 표시합니다."""
    # 검색 조건 가져오기
    search_username = request.args.get('search_username', '')
    start_date = request.args.get('start_date', get_current_time().strftime('%Y-%m-%d'))
    end_date = request.args.get('end_date', get_current_time().strftime('%Y-%m-%d'))
    search_status = request.args.get('search_status', '')
    search_registered = request.args.get('search_registered', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 페이지당 표시할 항목 수

    try:
        # 기본 쿼리 생성
        query = db.session.query(
            UserAccessLog.access_time,
            UserAccessLog.username,
            UserAccessLog.ip_address,
            UserAccessLog.action,
            UserAccessLog.success,
            UserAccessLog.error_message,
            UserAccessLog.is_registered_user
        )

        # 검색 조건 적용
        if search_username:
            query = query.filter(UserAccessLog.username.ilike(f'%{search_username}%'))
        if start_date:
            query = query.filter(UserAccessLog.access_time >= f"{start_date} 00:00:00")
        if end_date:
            query = query.filter(UserAccessLog.access_time <= f"{end_date} 23:59:59")
        if search_status:
            query = query.filter(UserAccessLog.success == (search_status == 'success'))
        if search_registered:
            query = query.filter(UserAccessLog.is_registered_user == (search_registered == 'true'))

        # 결과 정렬 (최신순)
        query = query.order_by(UserAccessLog.access_time.desc())
        
        # 페이징 처리
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        access_logs = pagination.items
        
        app.logger.debug(f"조회된 접속 로그 수: {len(access_logs)}")  # 디버깅을 위한 로그 추가
        
        return render_template('user_access_history.html',
                             access_logs=access_logs,
                             pagination=pagination,
                             search_username=search_username,
                             start_date=start_date,
                             end_date=end_date,
                             search_status=search_status,
                             search_registered=search_registered)
                             
    except Exception as e:
        app.logger.error(f"사용자 접속 내역 조회 중 오류 발생: {str(e)}")
        flash('접속 내역을 조회하는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('index'))

@app.route('/api/users/<int:user_id>/access-history')
@login_required
@admin_required
def get_user_access_history(user_id):
    """사용자의 접속 내역을 조회합니다."""
    try:
        # 사용자 존재 여부 확인
        user = User.query.get_or_404(user_id)
        
        # 접속 내역 조회 (최근 30일)
        thirty_days_ago = get_current_time() - timedelta(days=30)
        history = db.session.query(
            UserAccessLog.access_time,
            UserAccessLog.ip_address,
            UserAccessLog.success,
            UserAccessLog.error_message
        ).filter(
            UserAccessLog.username == user.username,
            UserAccessLog.access_time >= thirty_days_ago
        ).order_by(UserAccessLog.access_time.desc()).all()
        
        return jsonify({
            'success': True,
            'history': [{
                'access_time': entry.access_time.strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': entry.ip_address,
                'success': entry.success,
                'error_message': entry.error_message or '-'
            } for entry in history]
        })
        
    except Exception as e:
        app.logger.error(f"접속 내역 조회 중 오류 발생: {str(e)}")
        return jsonify({
            'success': False,
            'error': '접속 내역을 조회하는 중 오류가 발생했습니다.'
        }), 500

# API 엔드포인트
@app.route('/api/v1/encrypt', methods=['POST'])
@require_api_token
def api_encrypt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '요청 데이터가 없습니다.'}), 400

        text = data.get('text')
        key_id = data.get('key_id')
        program_name = data.get('program_name', 'Unknown')

        if not text or not key_id:
            return jsonify({'error': '필수 파라미터가 누락되었습니다.'}), 400

        # 키 조회
        key = Key.query.get(key_id)
        if not key:
            return jsonify({'error': '유효하지 않은 키 ID입니다.'}), 404
        if not key.active:
            return jsonify({'error': '폐기된 키입니다.'}), 400

        # 암호화 수행
        try:
            fernet = Fernet(derive_key(key.key_material, key.salt)[0])
            encrypted_text = fernet.encrypt(text.encode()).decode()

            # 로그 기록
            log = KeyAccessLog(
                key_id=key_id,
                access_time=get_current_time(),
                action='encrypt',
                ip_address=get_client_ip(),
                program_name=program_name,
                is_success=True,
                token=request.headers.get('X-API-Token')
            )
            db.session.add(log)
            db.session.commit()

            return jsonify({
                'encrypted_text': encrypted_text,
                'key_version': key.version
            })

        except Exception as e:
            # 암호화 실패 로그
            log = KeyAccessLog(
                key_id=key_id,
                access_time=get_current_time(),
                action='encrypt',
                ip_address=get_client_ip(),
                program_name=program_name,
                is_success=False,
                error_message=str(e),
                token=request.headers.get('X-API-Token')
            )
            db.session.add(log)
            db.session.commit()
            raise

    except Exception as e:
        app.logger.error(f"암호화 중 오류 발생: {str(e)}")
        result['message'] = f'처리 중 오류가 발생했습니다: {str(e)}'
            
    return render_template('text_encryption_test.html', form=form, result=result)

@app.route('/api/v1/decrypt', methods=['POST'])
@require_api_token
def api_decrypt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '요청 데이터가 없습니다.'}), 400

        encrypted_text = data.get('encrypted_text')
        key_id = data.get('key_id')
        program_name = data.get('program_name', 'Unknown')

        if not encrypted_text or not key_id:
            return jsonify({'error': '필수 파라미터가 누락되었습니다.'}), 400

        # 키 조회
        key = Key.query.get(key_id)
        if not key:
            return jsonify({'error': '유효하지 않은 키 ID입니다.'}), 404
        if not key.active:
            return jsonify({'error': '폐기된 키입니다.'}), 400

        # 복호화 수행
        try:
            fernet = Fernet(derive_key(key.key_material, key.salt)[0])
            decrypted_text = fernet.decrypt(encrypted_text.encode()).decode()

            # 로그 기록
            log = KeyAccessLog(
                key_id=key_id,
                access_time=get_current_time(),
                action='decrypt',
                ip_address=get_client_ip(),
                program_name=program_name,
                is_success=True,
                token=request.headers.get('X-API-Token')
            )
            db.session.add(log)
            db.session.commit()

            return jsonify({
                'decrypted_text': decrypted_text,
                'key_version': key.version
            })

        except Exception as e:
            # 복호화 실패 로그
            log = KeyAccessLog(
                key_id=key_id,
                access_time=get_current_time(),
                action='decrypt',
                ip_address=get_client_ip(),
                program_name=program_name,
                is_success=False,
                error_message=str(e),
                token=request.headers.get('X-API-Token')
            )
            db.session.add(log)
            db.session.commit()
            raise

    except Exception as e:
        app.logger.error(f"복호화 중 오류 발생: {str(e)}")
        result['message'] = f'처리 중 오류가 발생했습니다: {str(e)}'
            
    return render_template('text_encryption_test.html', form=form, result=result)

# API 엔드포인트에 대해 CSRF 보호 제외
csrf.exempt(api_encrypt)
csrf.exempt(api_decrypt)

@app.route('/logs')
@login_required
@admin_required
def logs():
    """암호키 사용 내역 페이지를 표시합니다."""
    form = LogSearchForm()
    
    # 검색 조건 가져오기
    start_date = request.args.get('start_date', get_current_time().strftime('%Y-%m-%d'))
    end_date = request.args.get('end_date', get_current_time().strftime('%Y-%m-%d'))
    key_id = request.args.get('key_id', '')
    action = request.args.get('action', '')
    status = request.args.get('status', '')
    program_name = request.args.get('program_name', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # 페이지당 표시할 항목 수

    try:
        # 암호키 선택 옵션 설정
        keys = Key.query.all()
        form.key_id.choices = [('', '전체')] + [(str(k.id), k.name) for k in keys]
        
        # 기본 쿼리 생성
        query = db.session.query(KeyAccessLog, Key.name)\
            .outerjoin(Key, KeyAccessLog.key_id == Key.id)

        # 검색 조건 적용
        if key_id:
            query = query.filter(KeyAccessLog.key_id == key_id)
        if action:
            query = query.filter(KeyAccessLog.action == action)
        if status:
            is_success = (status == 'success')
            query = query.filter(KeyAccessLog.is_success == is_success)
        if start_date:
            query = query.filter(KeyAccessLog.access_time >= f"{start_date} 00:00:00")
        if end_date:
            query = query.filter(KeyAccessLog.access_time <= f"{end_date} 23:59:59")
        if program_name:
            query = query.filter(KeyAccessLog.program_name.ilike(f'%{program_name}%'))

        # 결과 정렬 (최신순)
        query = query.order_by(KeyAccessLog.access_time.desc())
        
        # 페이징 처리
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        logs = pagination.items
        
        # 검색 파라미터 유지
        search_params = {
            'start_date': start_date,
            'end_date': end_date,
            'key_id': key_id,
            'action': action,
            'status': status,
            'program_name': program_name
        }
        
        return render_template('logs.html',
                             form=form,
                             logs=logs,
                             pagination=pagination,
                             search_params=search_params)
                             
    except Exception as e:
        app.logger.error(f"암호키 사용 내역 조회 중 오류 발생: {str(e)}")
        flash('암호키 사용 내역을 조회하는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('index'))

@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def users():
    """사용자 관리 페이지를 표시합니다."""
    form = UserForm()
    
    if request.method == 'GET':
        # 검색 조건 가져오기
        search_username = request.args.get('search_username', '')
        search_role = request.args.get('search_role', '')
        search_status = request.args.get('search_status', '')
        
        # 사용자 쿼리 생성
        query = User.query
        
        if search_username:
            query = query.filter(User.username.ilike(f'%{search_username}%'))
        if search_role:
            query = query.filter(User.is_admin == (search_role == 'admin'))
        if search_status:
            query = query.filter(User.is_active == (search_status == 'active'))
            
        users = query.order_by(User.username).all()
        return render_template('users.html', users=users, form=form)
    
    if request.method == 'POST':
        if not request.is_json:
            if form.validate_on_submit():
                try:
                    user = User(
                        username=form.username.data,
                        username_kor=form.username_kor.data,
                        email=form.email.data,
                        is_admin=(form.is_admin.data == '1'),
                        is_active=True,
                        created_at=get_current_time()
                    )
                    user.set_password(form.password.data)
                    db.session.add(user)
                    db.session.commit()
                    flash('사용자가 성공적으로 생성되었습니다.')
                    return redirect(url_for('users'))
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"사용자 생성 중 오류 발생: {str(e)}")
                    flash('사용자 생성 중 오류가 발생했습니다.', 'error')
                    return redirect(url_for('users'))
            return render_template('users.html', form=form)

@app.route('/about')
@login_required
def about():
    """시스템 소개 페이지를 표시합니다."""
    return render_template('about.html')

@app.route('/token/<int:token_id>/detail')
@login_required
def token_detail(token_id):
    """API 토큰의 상세 정보를 표시합니다."""
    try:
        # 토큰 조회
        token = ApiToken.query.get_or_404(token_id)
        
        # 토큰 소유자 또는 관리자만 접근 가능
        if token.creator_id != current_user.id and not current_user.is_admin:
            flash('권한이 없습니다.', 'error')
            return redirect(url_for('manage_tokens'))
        
        return render_template('token_detail.html', token=token)
        
    except Exception as e:
        app.logger.error(f"토큰 상세 정보 조회 중 오류 발생: {str(e)}")
        flash('토큰 상세 정보를 조회하는 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('manage_tokens'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True) 