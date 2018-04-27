from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


#
# autostart must be False if we intend to dynamically create the database.
#
db = SqliteQueueDatabase(None, autostart=False)


class BinaryDetonationResult(Model):
    md5 = CharField()
    last_scan_date = DateField(null=True)
    last_success_msg = CharField(default='', null=True)

    last_error_msg = CharField(default='', null=True)
    last_error_date = DateField(null=True)

    score = IntegerField(default=0)
    stop_future_scans = BooleanField(default=False)

    class Meta:
        database = db