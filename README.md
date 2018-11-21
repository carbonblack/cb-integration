# Cb Integration v2

Dependencies:
Runtime: requires docker,docker-compose, git
Development: docker,git,yarn,npm10+ v

1. Install Docker and docker-compose for your target operating system

	https://docs.docker.com/install/

2. Use git to download the cb-integration (or CBSDK)  project 
    git clone https://github.com/carbonblack/cb-integration

Optional: Confiure and run the yara-connector
The yara-connector has been provided of an example of the new style of connectors
that use the new CBSDK. It comes 'baked in' to the cbsdk, both as a functional 
demonstration and to be used as an example for developers. 

The yaraconnector is not configured by default. 

3. the vol/<connectorname> directory houses the configuration, source code, etc
for each connector. Place a file called <connectorname>.conf in the directory
 of your chosen connector.
    1) vol/yaraconnector/yaraconnector.conf to configura the yara connector
        - Be certain to provide correct CbR server & rabbitmq credentials
    2) vol/<connectorname>/supervisord.conf - contains supervisord config
        - Supervisord manages other dependent sevices, etc and the connector itself
        - This file does not need to be modified by the user
    3) vol/<connectorname>/feed - directory for threat intel feed
        - The connector writes a feed.json to this directory which is available
        as 0.0.0.0:500/yaraconnector/feed.json
    4) vol/<connectorname>/db - directory for binary databases
        - The yaraconnector will write sqlite db to this dir containing analysis
    5) vol/yaraconnector/yara_rules - directory containing yara rules
        - A large number of stock rules are provided by default
        - set meta.score or all threats get a score of 100 in CbR.

3. Use docker-comopose to run
    docker-compose up 

# Dev

The docker-compose.yml in your cb-integration folder specifies a tagged 
image on dockerhub to use as the base for the cbsdk

You can alter this to build from the included dockerfile, or point to your own image.
Simpy comment out the image: tag with a '#' symbol in docker-compose.yml
and reveal the build tag to build from the included dockerfile.

The included make file will use yarn, docker-compose to build the image for
cbsdk. 

Use 'make build' to build everything, or 'make ui' to build just the ui.

Use 'docker-compose build' to build just the docker image.

Change the log_driver: "none" in the docker-compose to enable verbose debug logging - by default
the services will log to files in the vol/<connectorname> directory as specified
in each connectors supervisord.conf file.

