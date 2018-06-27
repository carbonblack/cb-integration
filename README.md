# Cb Integration v2
Cb Integration v2

Starting out you do all this

	docker build -t cbsdk-base -f dockerfile.base .
	docker build -t cbsdk -f dockerfile .
	docker volume create cbsdk-conf
	docker run --rm -it -p 5000:5000 --mount source=cbsdk-conf,target=/conf cbsdk

during dev you do

	docker build -t cbsdk -f dockerfile .
	docker run --rm -it -p 5000:5000
	
To download and load a container
	
	docker pull askthedragon/cbsdk:0.8.0
	
Create a directory to house all config files

	mkdir ./vol
	
Now copy the image's directory structure so we can modify the config files as needed

	docker run --rm --mount type=bind,source="$(pwd)"/vol,target=/tmp --entrypoint cp askthedragon/cbsdk:0.8.0 -a /vol/. /tmp/
	
Modify the config files as needed
	
Run the image with the appropriate bind mount and port mapping

	docker run -d --name cb-yara-container --mount type=bind,source=/root/vol,target=/vol -p 5000:80 -p 9001:9001 askthedragon/cbsdk:0.8.0
	