FROM cbsdk

RUN apt-get install -y redis-server

#
# Copy over cbint
# Note this will be changed to pip install
#
COPY cbint /cbint

#
# copy setup.py
#
COPY setup.py /

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

COPY vol/supervisord/supervisord.conf.yara /vol/supervisord/supervisord.conf

#
# open ports
#
EXPOSE 80 9001

#
# Quick test to make sure we can import cbsdk
#
RUN python3 -c "import cbint"

RUN useradd -d /home/yara -ms /bin/bash yara

RUN chown -R yara /vol /connectors /cbint /var/log/
RUN chgrp -R yara /vol /connectors /cbint /var/log/
#
# Start supervisord
#
CMD ["/usr/bin/supervisord", "-c", "/vol/supervisord/supervisord.conf"]
