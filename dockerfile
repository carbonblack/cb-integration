FROM cbsdk-base

#
# copy setup.py
#
COPY setup.py /

#
# Copy over cbint
# Note this will be changed to pip install
#
COPY cbint /cbint

#
# run the install script for cbsdk
#
RUN python3 setup.py install

#
# copy credential file
#
COPY credentials.response /etc/carbonblack/

#
# copy over the connectors/samples
#
COPY connectors /connectors

#
# copy over conf files
#
COPY conf /conf

COPY /conf/nginx/nginx.conf /etc/nginx/nginx.conf
COPY /conf/nginx/nginx-yara.conf /etc/nginx/conf.d/yara.conf

#
# open ports
#
EXPOSE 22 80 5000

#
# Quick test to make sure we can import cbsdk
#
RUN python3 -c "import cbint"

#
# Start supervisord
#
CMD ["/usr/bin/supervisord", "-c", "/conf/supervisord/supervisord.conf"]