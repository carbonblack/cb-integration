build: all

all: ui container

ui: 
	cd cbsdkui && yarn build 		
container:
	docker-compose build
