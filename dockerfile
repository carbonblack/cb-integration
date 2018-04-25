FROM python:3.6

RUN apt-get update && apt-get install -y nginx supervisor

#
# copy setup.py and cbsdk directory
#
COPY setup.py /
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY cbint /cbint
COPY credentials.response /etc/carbonblack/

#
# run the install script for cbsdk
#
RUN python3 setup.py install

#
# copy over the connectors/samples
#
COPY samples /samples

#
# Change working directory
#
WORKDIR /samples/yara

#
# open port 5000
#
EXPOSE 5000

#
# Quick test to make sure we can import cbsdk
#
RUN python3 -c "import cbint"

#
# Actually run the the yara connector
#
#CMD [ "python3", "yara_connector.py" ]
CMD ["/usr/bin/supervisord"]

