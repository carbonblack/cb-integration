#!/usr/bin/env python

import sys

sys.path.insert(0, "src/")

from cbint import version
from setuptools import setup

setup(
    name='python-cb-integration',
    version=version.__version__,
    url='http://www.bit9.com/',
    license='MIT',
    author='Carbon Black',
    author_email='dev-support@bit9.com',
    description='Carbon Black Integration Library',
    long_description=__doc__,
    packages=['cbint', 'cbint.utils'],
    package_data={'cbint': ['utils/templates/*']},
    package_dir = {'': 'src'},
    platforms='any',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: MIT',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
