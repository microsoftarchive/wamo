#!/usr/bin/env python

from distutils.core import setup

setup(name='azuremonitor',
      version='0.1',
      description='Windows Azure monitor',
      author='Jeff Mendoza',
      author_email='jemendoz@microsoft.com',
      url='https://pypi.python.org/pypi/azuremonitor/',
      packages=['azuremonitor'],
      requires=['argparse', 'azure', 'OpenSSL'],
      scripts=['check_azure.py'],
     )
