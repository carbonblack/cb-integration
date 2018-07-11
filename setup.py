from setuptools import setup, find_packages
import os

setup(
    name='cbint',
    version='2.0.0',
    description='Carbon Black Developer Network Integration Framework',
    url='https://github.com/carbonblack/cbsdk',
    author='Carbon Black Developer Network',
    author_email='dev-support@carbonblack.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
    ],

    keywords='carbonblack bit9 response defense',
    packages=find_packages(exclude=('samples', 'tests', 'docs')),
    install_requires=[
        'cbapi',
        'peewee',
        'requests',
        'requests[security]',
        'attrdict',
        'cachetools',
        'pyyaml',
        'pika',
        'prompt_toolkit',
        'pygments',
        'python-dateutil',
        'protobuf',
        'yara-python',
        'grpcio',
        'flask',
        'celery',
        'redis'
    ],
    project_urls={
        'Bug Reports': 'https://github.com/carbonblack/cb-integration/issues',
    },
    data_files=[('cbint/static', [os.path.join('cbint', 'static', f) for f in files])
                for root, dirs, files in os.walk('cbint/static')]

)
