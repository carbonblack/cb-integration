from peewee import *
from playhouse.sqliteq import SqliteQueueDatabase

db = SqliteQueueDatabase('binary.db', timeout=30)

class BinaryDetonationResult(Model):
    md5 = CharField()
    last_scan_date = DateField(null=True)
    success_msg = CharField(default='', null=True)

    last_error_msg = CharField(default='', null=True)
    last_error_date = DateField(null=True)

    score = IntegerField(default=0)
    stop_future_scans = BooleanField(default=False)

    class Meta:
        database = db
