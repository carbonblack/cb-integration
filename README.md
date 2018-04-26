# Cb Integration v2
Cb Integration v2


	docker build -t cbsdk-base -f dockerfile.base .
	docker build -t cbsdk -f dockerfile .
	docker volume create cbsdk-conf
	docker run --rm -it -p 5000:5000 --mount source=cbsdk-conf,target=/conf cbsdk
