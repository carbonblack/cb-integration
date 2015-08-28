__author__ = 'jgarman'

from cbint.utils.detonation import DetonationDaemon
import unittest
import tempfile
import os
import sqlite3
import glob
import json
import shutil


class TestDaemon(DetonationDaemon):
    pass


class TestLegacyMigration(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.mkdtemp()
        self.data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        config_path = os.path.join(self.data_path, "daemon.conf")
        self.daemon = TestDaemon("testdaemon", configfile=config_path, work_directory=self.temp_directory,
                                 logfile=os.path.join(self.temp_directory, 'test.log'), debug=True)
        self.daemon.initialize_queue()

    def test_migration(self):
        shutil.copytree(os.path.join(self.data_path, "legacy_files"),
                        os.path.join(self.temp_directory, "import_directory"))
        self.daemon.migrate_legacy_reports(os.path.join(self.temp_directory, "import_directory"))
        conn = sqlite3.connect(self.daemon.database_file)

        for fn in glob.glob(os.path.join(self.data_path, "legacy_files", "*")):
            fileid = json.load(open(fn, 'rb'))['iocs']['md5'][0]
            cur = conn.cursor()
            cur.execute("SELECT * FROM binary_data WHERE md5sum=?", (fileid,))
            results = cur.fetchone()

            self.assertIsNotNone(results, msg="Did not import md5sum %s" % fileid)

        # remaining_files = glob.glob(os.path.join(self.temp_directory, "import_directory", "*"))
        # self.assertItemsEqual([], remaining_files, msg="Files remaining: %s" % remaining_files)
        self.assertTrue(os.path.isfile(os.path.join(self.temp_directory, "import_directory", ".migrated")))

        return True
