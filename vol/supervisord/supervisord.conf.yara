[supervisord]
loglevel=debug        ; (log level;default info; others: debug,warn,trace)
nodaemon=true         ; (start in foreground if true;default false)

[inet_http_server]
port=*:9001

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;" -c /vol/nginx/nginx.conf
username=www-data
autostart=true
autorestart=true

[program:redis]
command=/usr/bin/redis-server
user=root
autostart=true
autorestart=true

[program:yara]
directory=/connectors/yara
command=python3 main.py
user=root
autostart=true
autorestart=true

[program:yara_workers]
user=yara
directory=/connectors/yara
command=celery -A tasks worker --loglevel=info -f /var/log/yara_workers.log
autostart=true
autorestart=true