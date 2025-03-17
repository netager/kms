import multiprocessing

# 바인딩할 주소와 포트
bind = "0.0.0.0:8001"

# 워커 프로세스 수
workers = multiprocessing.cpu_count() * 2 + 1

# 워커 클래스 설정
worker_class = 'sync'

# 타임아웃 설정
timeout = 120

# 로그 레벨 설정
loglevel = 'debug'

# 로그 파일 설정
errorlog = 'error.log'
accesslog = 'access.log'
access_log_format = '%({x-real-ip}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# SSL 설정 (필요한 경우)
# keyfile = 'ssl/key.pem'
# certfile = 'ssl/cert.pem'

# 기타 설정
keepalive = 2
max_requests = 1000
max_requests_jitter = 50
graceful_timeout = 30 