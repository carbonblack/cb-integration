# Cb Integration v2
Cb Integration v2

Starting out you do all this

	docker build -t cbsdk-base -f dockerfile.base .
	docker build -t cbsdk -f dockerfile .
	docker volume create cbsdk-conf
	docker run --rm -it -p 5000:5000 --mount source=cbsdk-conf,target=/conf cbsdk

during dev you do

	docker build -t cbsdk -f dockerfile .
	docker run --rm -it -p 5000:5000 --mount source=cbsdk-conf,target=/conf cbsdk