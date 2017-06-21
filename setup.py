#!/usr/bin/env python

from setuptools import setup

setup(
    name='cbint',
    version='0.8.10',
    url='https://developer.carbonblack.com/',
    license='MIT',
    author='Carbon Black',
    author_email='dev-support@carbonblack.com',
    description='Carbon Black Integration Library',
    long_description=__doc__,
    packages=['cbint', 'cbint.utils', 'cbint.utils.detonation'],
    package_data={'cbint': ['utils/templates/*'], 'cbint.utils.detonation': ['templates/*']},
    package_dir = {'': 'src'},
    platforms='any',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    install_requires=['flask', 'python-dateutil', 'netifaces', 'cbapi==1.1.1', 'cbfeeds==0.8.0']
)
