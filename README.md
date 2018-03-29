# Cb Integration v2
Cb Integration v2 description here

# building protobuffer code

	python -m grpc_tools.protoc -I ./proto/ --python_out=. --grpc_python_out=. proto/cbint/cbint.proto 
