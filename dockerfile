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
# copy over the connectors/samples
#
COPY connectors /connectors

#
# copy over conf files
#
COPY vol /vol

#
# open ports
#
EXPOSE 80

#
# Quick test to make sure we can import cbsdk
#
RUN python3 -c "import cbint"

#
# Start supervisord
#
CMD ["/usr/bin/supervisord", "-c", "/vol/supervisord/supervisord.conf"]