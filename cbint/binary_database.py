import logging

from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#
# autostart must be False if we intend to dynamically create the database.
#
db = SqliteQueueDatabase(None, autostart=False)
# db = PostgresqlDatabase('postgres',
#                         user='postgres',
#                         password='mysecretpassword',
#                         host='localhost',
#                         port=5432)


class Binary(Model):
    class Meta:
        database = db
    md5 = CharField(index=True)
    stop_future_scans = BooleanField(default=False)
    from_rabbitmq = BooleanField(default=False)
    server_added_timestamp = DateTimeField()
    force_rescan = BooleanField(default=False)
    misc = CharField(default='')
    available = BooleanField(default=False)


class DetonationResult(Model):
    md5 = CharField(index=True)
    scan_date = DateTimeField(null=True)
    success_msg = CharField(default='', null=True)
    error_msg = CharField(default='', null=True)
    score = IntegerField(default=0,null=True)
    scanner = CharField(null=True)
    class Meta:
        database = db
