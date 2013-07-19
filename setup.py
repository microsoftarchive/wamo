#!/usr/bin/env python

# Copyright 2013 MS Open Tech
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#setup.py: distutils setup script

from distutils.core import setup

with open('README') as file:
    long_description = file.read()

setup(name='azuremonitor',
      version='0.1',
      description='Windows Azure Monitor',
      author='Jeff Mendoza',
      author_email='jeffmendoza@live.com',
      url='https://pypi.python.org/pypi/azuremonitor/',
      license='Apache License, Version 2.0',
      packages=['azuremonitor'],
      requires=['argparse', 'azure', 'OpenSSL', 'pyodbc'],
      scripts=['check_azure_compute.py',
               'check_azure_ad.py',
               'check_azure_sql.py',
               'check_azure_storage.py',
               'check_azure_paas.py'],
      long_description=long_description,)
