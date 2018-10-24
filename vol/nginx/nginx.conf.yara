events {
    worker_connections  1024;
}

http {
	server {
		listen         80;
		listen         [::]:80;

		gzip             on;
		gzip_comp_level  3;
		gzip_types       text/plain text/css application/javascript application/json image/*;

		location /feed.json {
			alias /vol/yara/feed/feed.json;
		}

		location = /supervisor {
			proxy_pass http://localhost:9001;
		}

		location / {
			proxy_pass http://localhost:7000;
		}
	}
}
