# Cb Integration v2 SDK 
An extensible framework for developing integrations with Carbon Black API's.
The V2 CbSDK manages 'connectors' within a docker container as python daemons 
under the management of supervisorD.
Developers can use the interfaces (cbint.Detonation, and cbint.Integration) to  
quickly write new connectors for threat intel, or arbitrary purpose.

The CbSDK UI is available over localhost:5000, providing at present a basic interface
for viewing and manipulating the state of connectors.

Dependencies:
Runtime: requires docker,docker-compose, git
Development: docker,git,yarn,npm10+ v

1. Install Docker and docker-compose for your target operating system

	https://docs.docker.com/install/

2. Use git to download the CBSDK project, and move into the directory 
    git clone https://github.com/carbonblack/cb-integration

3. Use docker-comopose to run
    docker-compose up 


Optional: Confiure and run the yara-connector
The yara-connector has been provided of an example of the new style of connectors
that use the new CBSDK. It comes 'baked in' to the cbsdk, both as a functional 
demonstration of the improved CBSDK  and to be used as stock example for devs  
who seek to write their own custom ingegrations with the CBSDK and CBAPI for python.

The yaraconnector is not configured by default. 

4. the vol/<connectorname> directory houses the configuration, source code, etc
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
        - the default score is 100, set meta.score in your rules to override 

6. Use docker-comopose to run/restart
    docker-compose up 

# Dev

The process of developing a new connector has been simplified to creating a 
python program in vol/<myconnectorname>/ and configuring supervisord to manage it.
The latter is done by placing a supevisord.conf in vol/<connectorname>. 
Developers should use the yaraconnector as a working-example.

Development dependencies are a little more involved, ther react-ui for the app 
requires the NPM10+ and YARN, as well as docker and compose to build.

The docker-compose.yml in your cb-integration folder specifies a tagged 
image on dockerhub to use as the base for the cbsdk

You can alter this to build from the included dockerfile, or point to your own image.
Simpy comment out the image: tag with a '#' symbol in docker-compose.yml
and reveal the build tag to build from the included dockerfile.

This is useful for adding new dependencies, etc that must be available. 
You can extend the existing cbdevnetwork/cbsdk image using the FROM directive in
a dockerfile, etc.

The included make file will use yarn, docker-compose to build the image for
cbsdk. First you must remove the image: line from the compose yaml, and comment-in 
the comment-out lines for `build: .`  and `dockerfile`. 

Now the cbsdk will build locally rather than pulling from dockerhub.

Use 'make build' to build everything, or 'make ui' to build just the ui.

Use 'docker-compose build' to build just the docker image.

Change the log_driver: "none" in the docker-compose to enable verbose logging.
By default, the services will log to files in the vol/<connectorname> directory 

