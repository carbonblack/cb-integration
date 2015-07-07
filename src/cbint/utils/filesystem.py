import os
import errno


def ensure_directory_exists(directory):
    """
    Checks to make sure a directory exists, and if not, creates it
    """
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise
