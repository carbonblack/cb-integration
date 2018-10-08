# Cb Integration v2

## Yara Docker Container Installation

1. Install Docker

	https://docs.docker.com/install/

2. Download the yara docker container

	```
	docker pull cbdevnetwork/cb-yara-container:latest
	```

1. Create a directory that will store your configuration files.  Let's call it `./yara-vol`.

	```
	mkdir ./yara-vol
	```
	
2. Copy the contents of the docker image configuration directory locally.

	```
	docker run --rm -v $(pwd)/yara-vol:/tmp cbdevnetwork/cb-yara-container:latest sh -c "cp -r /vol/* /tmp"
	```
	
3. Modify the local file `./yara-vol/yara/yara.conf.template` and place in `./yara-vol/yara/yara.conf`

    ```
    cp ./yara-vol/yara/yara.conf.template ./yara-vol/yara/yara.conf
	```

	Ensure the Cb Response Server URL and API Key are correct.

4. Run the container with `yara-vol` directory bind mounted to `/vol` from within the container.

	```
	docker run -d --name cb-yara-container --mount type=bind,source=$(pwd)/yara-vol,target=/vol -p 5000:80 -p 9001:9001 cbdevnetwork/cb-yara-container:latest
	```
	
5. View `./yara-vol/yara.log` for debugging information

	```
	less ./yara-vol/yara.log
	```
	
6. The yara container listens on port 5000.  This can be changed by the docker run command above.  
   To view the feed use `curl localhost:5000/feed.json`.

## Developer Steps

Starting out you do all this


	docker build -t cbsdk -f dockerfile.cbsdk .
	docker build -t cb-yara-container -f dockerfile.yara .
	docker run -d --name cb-yara-instance --mount type=bind,source="$(pwd)"/vol,target=/vol -p 5000:80 -p 9001:9001 cb-yara-container
	docker exec -it /bin/bash cb-yara-instance
	docker rm cb-yara-instance
	
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
	
