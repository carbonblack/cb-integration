# Cb Integration v2

## Yara Docker Container Installation

requires docker, git for production and docker,git,yarn,npm10+ for dev

1. Install Docker and docker-compose for your target operating system

	https://docs.docker.com/install/

2. Use git to download the project 
    git clone https://github.com/carbonblack/cb-integration

3. the vol/<connectorname> redictory houses the configuration, source code, etc
for each connector. Place a file called <connectorname>.conf in the directory
 of your chosen connector
    ex) edit vol/yaraconnector/yaraconnector.conf to configura the yara connector

3. Use docker-comopose to run
    docker-compose up 

# Dev

The docker-composs.yml in your cb-integration folder specifies a tagged 
image on dockerhub to use as the base for the cbsdk

You can alter this to build from the included dockerfile, or your own image.
Simpy comment out the image: tag with a '#' symbol in docker-compose.yml
and reveal the build tag to build from the included dockerfile.

The included make file will use yarn, docker-compose to build the image for
cbsdk. 
Use 'make build' to build everything, or 'make ui' to build just the ui.

Use 'docker-compose build' to build just the docker image.

