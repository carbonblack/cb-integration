from setuptools import setup, find_packages

setup(
    name='cbint',
    version='1.0.0',
    description='Carbon Black Developer Network Integration Framework',
    url='https://github.com/carbonblack/cb-integration',
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
    packages=find_packages(exclude=('samples','tests', 'docs')),
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
        'protobuf'
    ],
    project_urls={
        'Bug Reports': 'https://github.com/carbonblack/cb-integration/issues',

    },
)
