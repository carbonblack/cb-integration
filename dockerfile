FROM cbsdk-base

#
# copy setup.py and cbsdk directory
#
COPY setup.py /
COPY cbint /cbint
COPY credentials.response /etc/carbonblack/

#
# copy over the connectors/samples
#
COPY connectors /connectors

#
# copy over conf files
#
COPY conf /conf

#
# open port 5000
#
EXPOSE 5000

#
# Quick test to make sure we can import cbsdk
#
RUN python3 -c "import cbint"

#
# Sanity Check
#
CMD ["python3", "-c", "import cbint"]

#
# Start supervisord
#
CMD ["/usr/bin/supervisord", "-c", "/conf/supervisord/supervisord.conf"]