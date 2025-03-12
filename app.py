from flask import Flask, render_template, flash, redirect, url_for, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from datetime import datetime
from config import Config
import os
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
import yaml
import re
import requests
import pytz
import json

app = Flask(__name__)
app.config.from_object(Config)

# CSRF 보호 설정
csrf = CSRFProtect(app)

# 로그인 관리자 설정
login = LoginManager(app)
login.login_view = 'login'  # 로그인 뷰 함수명
login.login_message = '이 페이지에 접근하려면 로그인이 필요합니다.'
login.login_message_category = 'info'

# 에러 핸들러 추가
@app.errorhandler(403)
def forbidden_error(error):
    if not current_user.is_authenticated:
        flash('이 페이지에 접근하려면 로그인이 필요합니다.', 'warning')
        return redirect(url_for('login', next=request.url))
    flash('이 페이지에 대한 접근 권한이 없습니다.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(401)
def unauthorized_error(error):
    flash('이 페이지에 접근하려면 로그인이 필요합니다.', 'warning')
    return redirect(url_for('login', next=request.url))

# 한국 시간대 설정
KST = pytz.timezone('Asia/Seoul')

def get_current_time():
    """현재 한국 시간을 반환합니다."""
    return datetime.now(KST)

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
    username = StringField('사용자명', validators=[DataRequired()])
    email = EmailField('이메일', validators=[DataRequired(), Email()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    password2 = PasswordField('비밀번호 확인', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('가입하기')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('이미 사용 중인 사용자명입니다.')

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
        ('inactive', '비활성')
    ], default='active')
    submit = SubmitField('검색')

# 암호화 테스트 폼
class EncryptionTestForm(FlaskForm):
    server_url = StringField('서버 URL', validators=[DataRequired()], default='http://localhost:8000')
    key_id = SelectField('암호키 선택', coerce=int, validators=[DataRequired()])
    api_token = SelectField('API 토큰', coerce=int, validators=[DataRequired()])
    program_name = StringField('프로그램명', validators=[DataRequired()])
    plaintext = TextAreaField('평문', validators=[DataRequired()])
    submit = SubmitField('암호화/복호화')

# YAML 복호화 테스트 폼
class YamlDecryptionTestForm(FlaskForm):
    server_url = StringField('서버 URL', validators=[DataRequired()], default='http://localhost:8000')
    key_id = SelectField('암호키 선택', coerce=int, validators=[DataRequired()])
    api_token = SelectField('API 토큰', coerce=int, validators=[DataRequired()])
    program_name = StringField('프로그램명', validators=[DataRequired()])
    yaml_file = FileField('YAML 파일', validators=[DataRequired()])
    submit = SubmitField('복호화')

# 로그인 폼
class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    submit = SubmitField('로그인')

# 로그 검색 폼 추가
class LogSearchForm(FlaskForm):
    key_id = SelectField('암호키', choices=[('', '전체')], default='', coerce=str)
    action = SelectField('작업 유형', choices=[
        ('', '전체'),
        ('encrypt', '암호화'),
        ('decrypt', '복호화'),
        ('get_key', '키조회')
    ], default='')
    status = SelectField('상태', choices=[
        ('', '전체'),
        ('success', '성공'),
        ('fail', '실패')
    ], default='')
    submit = SubmitField('검색')

# 모델 정의
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)

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
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'))
    access_time = db.Column(db.DateTime, default=get_current_time)
    action = db.Column(db.String(32))
    ip_address = db.Column(db.String(45))
    program_name = db.Column(db.String(100))
    is_success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500))
    token = db.Column(db.String(64))  # API 토큰 값 저장

# API 토큰 모델
class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=get_current_time)
    last_used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

# API 토큰 폼
class ApiTokenForm(FlaskForm):
    description = StringField('설명', validators=[DataRequired()])
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
    if not current_user.is_authenticated:
        return render_template('index.html', title='홈')
    return render_template('index.html', title='홈')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('잘못된 사용자명 또는 비밀번호입니다', 'error')
            return redirect(url_for('login'))
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
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
        
        # 히스토리에 이전 키 정보 저장
        key_history = KeyHistory(
            key_id=key.id,
            key_material=old_key_material,
            salt=old_salt,
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
    """암호키를 비활성화합니다."""
    key = Key.query.get_or_404(key_id)
    if not key.active:
        flash('이미 비활성화된 키입니다.')
        return redirect(url_for('keys'))
    
    # 키 비활성화 히스토리 기록
    key_history = KeyHistory(
        key_id=key.id,
        key_material=key.key_material,
        salt=key.salt,  # 이전 salt 저장
        version=key.version,
        action='deactivate',
        created_at=get_current_time(),
        rotated_by_id=current_user.id
    )
    db.session.add(key_history)
    
    # 키 비활성화
    key.active = False
    key.deactivated_at = get_current_time()
    db.session.commit()
    
    flash('키가 비활성화되었습니다.')
    return redirect(url_for('keys'))

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

@app.route('/text_encryption_test', methods=['GET', 'POST'])
@login_required
def text_encryption_test():
    # 사용 가능한 키 목록 가져오기
    keys = Key.query.filter_by(active=True).all()
    form = EncryptionTestForm()
    form.key_id.choices = [(key.id, key.name) for key in keys]
    
    # 사용 가능한 API 토큰 목록 가져오기
    tokens = ApiToken.query.filter_by(user_id=current_user.id, is_active=True).all()
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
                return render_template('text_encryption_test.html', form=form, result=result)
            
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
                return render_template('text_encryption_test.html', form=form, result=result)
            
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
    tokens = ApiToken.query.filter_by(user_id=current_user.id, is_active=True).all()
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
        request.user = User.query.get(api_token.user_id)
        return f(*args, **kwargs)
    return decorated

# API 토큰 관리 라우트
@app.route('/manage_tokens', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_tokens():
    """API 토큰 관리 페이지를 표시합니다."""
    form = ApiTokenForm()
    if form.validate_on_submit():
        token = secrets.token_urlsafe(32)
        api_token = ApiToken(
            token=token,
            user_id=current_user.id,
            description=form.description.data
        )
        db.session.add(api_token)
        db.session.commit()
        return redirect(url_for('manage_tokens', new_token=token))
    
    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(ApiToken.created_at.desc()).all()
    return render_template('api_tokens.html', form=form, tokens=tokens)

@app.route('/token/<int:token_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_token(token_id):
    """API 토큰을 비활성화합니다."""
    token = ApiToken.query.get_or_404(token_id)
    if token.user_id != current_user.id:
        return jsonify({'error': '권한이 없습니다.'}), 403
    
    token.is_active = False
    db.session.commit()
    flash('API 토큰이 폐기되었습니다.')
    return redirect(url_for('manage_tokens'))

# API 토큰 목록 조회 엔드포인트
@app.route('/api/tokens/list', methods=['GET'])
@login_required
def get_tokens():
    try:
        tokens = ApiToken.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).order_by(ApiToken.created_at.desc()).all()
        
        return jsonify({
            'tokens': [{
                'id': token.id,
                'token': token.token,
                'description': token.description,
                'created_at': token.created_at.isoformat() if token.created_at else None,
                'last_used_at': token.last_used_at.isoformat() if token.last_used_at else None,
                'is_active': token.is_active
            } for token in tokens]
        })
    except Exception as e:
        app.logger.error(f"API 토큰 조회 중 오류 발생: {str(e)}")
        return jsonify({'error': '토큰 목록을 가져오는데 실패했습니다.'}), 500

def get_client_ip():
    """클라이언트의 실제 IP 주소를 반환합니다."""
    # X-Forwarded-For 헤더 확인
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    # X-Real-IP 헤더 확인
    elif request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    # 직접 연결된 클라이언트의 IP
    return request.remote_addr

def validate_api_token(token):
    """API 토큰의 유효성을 검사합니다."""
    if not token:
        return None, '토큰이 제공되지 않았습니다.'
    
    api_token = ApiToken.query.filter_by(token=token).first()
    if not api_token:
        return None, '유효하지 않은 토큰입니다.'
    
    if not api_token.is_active:
        return None, '비활성화된 토큰입니다.'
    
    # 토큰의 마지막 사용 시간 업데이트
    api_token.last_used_at = get_current_time()
    db.session.commit()
    
    return api_token, None

@csrf.exempt
@app.route('/api/v1/encrypt', methods=['POST'])
@require_api_token
def api_encrypt():
    # 토큰 검증
    token = request.headers.get('X-API-Token')
    api_token, error = validate_api_token(token)
    data = request.get_json() or {}
    key_id = data.get('key_id')
    program_name = data.get('program_name', 'Unknown')

    if error:
        # 토큰 검증 실패 로그
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='encrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error,
            'error_detail': {
                'action': 'encrypt',
                'timestamp': get_current_time().isoformat()
            }
        }), 401

    # 프로그램명 검증
    if not program_name or program_name == 'Unknown':
        error_msg = '프로그램명은 필수 항목이며 "Unknown"일 수 없습니다.'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='encrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'encrypt',
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400

    if not data or 'text' not in data or 'key_id' not in data:
        error_msg = '필수 파라미터가 누락되었습니다. (text, key_id)'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='encrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'encrypt',
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400
    
    key = Key.query.get(data['key_id'])
    if not key or not key.active:
        error_msg = '유효하지 않은 키입니다.'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='encrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'encrypt',
                'key_id': key_id,
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400
    
    try:
        # 키와 salt를 함께 사용하여 키 유도
        derived_key, _ = derive_key(key.key_material, key.salt)
        f = Fernet(derived_key)
        
        # 암호화
        encrypted_text = f.encrypt(data['text'].encode()).decode()
        
        # 성공 로그
        log = KeyAccessLog(
            key_id=key.id,
            access_time=get_current_time(),
            action='encrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=True,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'encrypted_text': encrypted_text,
            'key_version': key.version,
            'request_info': {
                'key_id': key.id,
                'program_name': program_name,
                'token': token
            }
        })
    except Exception as e:
        error_msg = f'암호화 중 오류가 발생했습니다: {str(e)}'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='encrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'encrypt',
                'key_id': key_id,
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 500

@csrf.exempt
@app.route('/api/v1/decrypt', methods=['POST'])
@require_api_token
def api_decrypt():
    # 토큰 검증
    token = request.headers.get('X-API-Token')
    api_token, error = validate_api_token(token)
    data = request.get_json() or {}
    key_id = data.get('key_id')
    program_name = data.get('program_name', 'Unknown')

    if error:
        # 토큰 검증 실패 로그
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='decrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error,
            'error_detail': {
                'action': 'decrypt',
                'timestamp': get_current_time().isoformat()
            }
        }), 401

    # 프로그램명 검증
    if not program_name or program_name == 'Unknown':
        error_msg = '프로그램명은 필수 항목이며 "Unknown"일 수 없습니다.'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='decrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'decrypt',
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400

    if not data or 'encrypted_text' not in data or 'key_id' not in data:
        error_msg = '필수 파라미터가 누락되었습니다. (encrypted_text, key_id)'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='decrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'decrypt',
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400
    
    key = Key.query.get(data['key_id'])
    if not key or not key.active:
        error_msg = '유효하지 않은 키입니다.'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='decrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'decrypt',
                'key_id': key_id,
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400
    
    try:
        # 키와 salt를 함께 사용하여 키 유도
        derived_key, _ = derive_key(key.key_material, key.salt)
        f = Fernet(derived_key)
        
        # 복호화
        decrypted_text = f.decrypt(data['encrypted_text'].encode()).decode()
        
        # 성공 로그
        log = KeyAccessLog(
            key_id=key.id,
            access_time=get_current_time(),
            action='decrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=True,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'decrypted_text': decrypted_text,
            'key_version': key.version,
            'request_info': {
                'key_id': key.id,
                'program_name': program_name,
                'token': token
            }
        })
    except Exception as e:
        error_msg = f'복호화 중 오류가 발생했습니다: {str(e)}'
        app.logger.error(f"복호화 중 오류: {e}")
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='decrypt',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'decrypt',
                'key_id': key_id,
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 500

@app.route('/key/<int:key_id>')
@login_required
@admin_required
def key_detail(key_id):
    """암호키 상세 정보를 표시합니다."""
    key = db.session.query(Key, User.username)\
        .join(User, Key.created_by_id == User.id)\
        .filter(Key.id == key_id)\
        .first_or_404()
    
    # 폐기 일자 포맷팅
    deactivated_at = None
    if key[0].deactivated_at:
        deactivated_at = key[0].deactivated_at.strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('key_detail.html', 
                         key=key[0], 
                         creator=key[1],
                         deactivated_at=deactivated_at,
                         salt=key[0].salt)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/deployment_guide')
def deployment_guide():
    return render_template('deployment_guide.html')

@app.route('/api-docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/key_history/<int:history_id>')
@login_required
def get_key_history(history_id):
    # 키 히스토리 조회
    history = KeyHistory.query.get_or_404(history_id)
    
    # 해당 키에 대한 접근 권한 확인
    key = Key.query.get(history.key_id)
    if not key:
        return jsonify({'success': False, 'error': '키를 찾을 수 없습니다.'}), 404
    
    # 변경을 수행한 사용자 정보 조회
    rotated_by = User.query.get(history.rotated_by_id)
    
    return jsonify({
        'success': True,
        'history_detail': {
            'key_id': history.key_id,
            'key_material': history.key_material[:10] + '****************',  # 마스킹 처리
            'salt': history.salt[:10] + '****************',  # salt 정보 추가 및 마스킹 처리
            'version': history.version,
            'action': history.action,
            'created_at': history.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'rotated_by': rotated_by.username if rotated_by else '알 수 없음'
        }
    })

@app.route('/api/log_detail/<int:log_id>')
@login_required
def get_log_detail(log_id):
    # 로그 상세 정보 조회 (KeyAccessLog 테이블만 사용)
    log = KeyAccessLog.query.get_or_404(log_id)
    
    return jsonify({
        'success': True,
        'log_detail': {
            'id': log.id,
            'key_id': log.key_id,
            'action': log.action,
            'access_time': log.access_time.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': log.ip_address,
            'program_name': log.program_name,
            'is_success': log.is_success,
            'error_message': log.error_message if not log.is_success else None,
            'token': log.token
        }
    })

@app.route('/logs')
@login_required
def logs():
    search_form = LogSearchForm()
    
    # 페이지 번호와 페이지당 항목 수
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 검색 조건 처리
    key_id = request.args.get('key_id', '')
    action = request.args.get('action', '')
    status = request.args.get('status', '')

    # 암호키 옵션 설정
    keys = Key.query.all()
    search_form.key_id.choices = [('', '전체')] + [(str(k.id), f'{k.name} (ID: {k.id})') for k in keys]

    # 검색 폼의 선택된 값 유지
    search_form.key_id.data = key_id
    search_form.action.data = action
    search_form.status.data = status

    # 기본 쿼리 생성 (Key 테이블과 명시적 조인)
    query = db.session.query(KeyAccessLog, Key.name.label('key_name'))\
        .outerjoin(Key, KeyAccessLog.key_id == Key.id)

    # 검색 조건 적용
    if key_id:
        query = query.filter(KeyAccessLog.key_id == int(key_id))
    if action:
        query = query.filter(KeyAccessLog.action == action)
    if status:
        is_success = (status == 'success')
        query = query.filter(KeyAccessLog.is_success == is_success)

    # 결과 조회 (최신순) with 페이징
    pagination = query.order_by(KeyAccessLog.access_time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    
    return render_template('logs.html', 
                         logs=logs,
                         search_form=search_form,
                         pagination=pagination)

@app.route('/users')
@login_required
@admin_required
def users():
    """사용자 관리 페이지를 표시합니다."""
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/<int:id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(id):
    user = User.query.get_or_404(id)
    
    # 자기 자신의 관리자 권한은 변경할 수 없음
    if user.id == current_user.id:
        flash('자신의 관리자 권한은 변경할 수 없습니다.', 'error')
        return redirect(url_for('users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    flash(f'사용자 {user.username}의 관리자 권한이 {"부여" if user.is_admin else "해제"}되었습니다.')
    return redirect(url_for('users'))

@app.route('/users/<int:id>/change_password', methods=['POST'])
@login_required
@admin_required
def change_password(id):
    """관리자가 사용자의 비밀번호를 변경합니다."""
    user = User.query.get_or_404(id)
    
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not new_password or not confirm_password:
        flash('새 비밀번호를 입력해주세요.', 'error')
        return redirect(url_for('users'))
    
    if new_password != confirm_password:
        flash('비밀번호가 일치하지 않습니다.', 'error')
        return redirect(url_for('users'))
    
    # 비밀번호 복잡도 검증
    if len(new_password) < 8:
        flash('비밀번호는 8자 이상이어야 합니다.', 'error')
        return redirect(url_for('users'))
    
    if not any(c.isupper() for c in new_password):
        flash('비밀번호에는 대문자가 포함되어야 합니다.', 'error')
        return redirect(url_for('users'))
    
    if not any(c.islower() for c in new_password):
        flash('비밀번호에는 소문자가 포함되어야 합니다.', 'error')
        return redirect(url_for('users'))
    
    if not any(c.isdigit() for c in new_password):
        flash('비밀번호에는 숫자가 포함되어야 합니다.', 'error')
        return redirect(url_for('users'))
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in new_password):
        flash('비밀번호에는 특수문자가 포함되어야 합니다.', 'error')
        return redirect(url_for('users'))
    
    user.set_password(new_password)
    db.session.commit()
    
    flash(f'사용자 {user.username}의 비밀번호가 변경되었습니다.', 'success')
    return redirect(url_for('users'))

def derive_key(key_material, salt=None):
    """키 유도 함수: 키 자료로부터 Fernet 키를 생성합니다."""
    if salt is None:
        # 새로운 salt 생성 (32바이트)
        salt = secrets.token_bytes(32)
    elif isinstance(salt, str):
        # DB에서 읽어온 salt 문자열을 바이트로 변환
        salt = bytes.fromhex(salt)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key_bytes = key_material.encode()
    key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
    
    # salt를 16진수 문자열로 변환하여 반환
    return key, salt.hex()

@app.route('/health')
def health_check():
    """서버 상태 확인을 위한 헬스체크 엔드포인트"""
    try:
        # 데이터베이스 연결 확인
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@csrf.exempt
@app.route('/api/v1/key', methods=['POST'])
@require_api_token
def api_get_key():
    # 토큰 검증
    token = request.headers.get('X-API-Token')
    api_token, error = validate_api_token(token)
    data = request.get_json() or {}
    key_id = data.get('key_id')
    program_name = data.get('program_name', 'Unknown')

    if error:
        # 토큰 검증 실패 로그
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='get_key',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error,
            'error_detail': {
                'action': 'get_key',
                'timestamp': get_current_time().isoformat()
            }
        }), 401

    # 프로그램명 검증
    if not program_name or program_name == 'Unknown':
        error_msg = '프로그램명은 필수 항목이며 "Unknown"일 수 없습니다.'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='get_key',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'get_key',
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400

    if not key_id:
        error_msg = '필수 파라미터가 누락되었습니다. (key_id)'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='get_key',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'get_key',
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400
    
    key = Key.query.get(key_id)
    if not key or not key.active:
        error_msg = '유효하지 않은 키입니다.'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='get_key',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'get_key',
                'key_id': key_id,
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 400
    
    try:
        # 성공 로그
        log = KeyAccessLog(
            key_id=key.id,
            access_time=get_current_time(),
            action='get_key',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=True,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'key_material': key.key_material,
            'salt': key.salt,
            'key_version': key.version,
            'request_info': {
                'key_id': key.id,
                'program_name': program_name,
                'token': token
            }
        })
    except Exception as e:
        error_msg = f'키 요청 중 오류가 발생했습니다: {str(e)}'
        log = KeyAccessLog(
            key_id=key_id,
            access_time=get_current_time(),
            action='get_key',
            ip_address=get_client_ip(),
            program_name=program_name,
            is_success=False,
            error_message=error_msg,
            token=token
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({
            'error': error_msg,
            'error_detail': {
                'action': 'get_key',
                'key_id': key_id,
                'program_name': program_name,
                'timestamp': get_current_time().isoformat()
            }
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True) 