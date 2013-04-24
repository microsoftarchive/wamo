#!/usr/bin/python

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
#check_azure_compute.py: Azure compute monitor script

import argparse
import os
import sys
import azure
import logging
from azure.servicemanagement import ServiceManagementService
from azuremonitor.publishsettings import PublishSettings


def handle_args():
    """Create the parser, parse the args, and return them."""
    parser = argparse.ArgumentParser(description='Check Azure Compute',
                                     epilog='(c) MS Open Tech')
    parser.add_argument('hostname', help='hosted service to check')
    parser.add_argument(
        '-p', '--publish-settings',
        required=True,
        help='.publishsettings file to authenticate with azure',
        dest='psfile')
    parser.add_argument('-a', '--all', action='store_true',
                        help='check all hosted services, ignores hostname')
    parser.add_argument('-v', '--verbose', action='count', 
                        default=0, help='verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    return parser.parse_args()


def check_for_errors_all(management):
    """Check the status of all hosted services, and return a list of errors."""
    hosted_services = management.list_hosted_services()
    errors = []
    if not hosted_services:
        errors.append('No hosted services found')
    for service in hosted_services:
        errors_host = check_for_errors(management, service.service_name)
        if errors_host:
            errors.append(' '.join(('{0}:'.format(service.service_name), errors_host)))
    return '; '.join(errors)


def check_for_errors(management, hostname):
    """Check the status of hostname, and return a list of errors."""
    errors = []
    try:
        service = management.get_hosted_service_properties(
            hostname,
            embed_detail=True)
    except azure.WindowsAzureMissingResourceError, error:
        errors.append('Hosted service {0} not found'.format(hostname))
        return ', '.join(errors)
    if service.hosted_service_properties.status != 'Created':
        errors.append('Service status: {0}'.format(service.hosted_service_properties.status))
    if not service.deployments:
        errors.append('No deployments found')
    for deployment in service.deployments:
        if deployment.status != 'Running':
            errors.append('Deployment status: {0}'.format(deployment.status))
        if not deployment.role_instance_list:
            errors.append('No role instances found')
        for role_inst in deployment.role_instance_list:
            if role_inst.power_state != 'Started':
                errors.append('Power state: {0}'.format(role_inst.power_state))
            if role_inst.instance_status != 'ReadyRole':
                errors.append('Role status: {0}'.format(role_inst.instance_status))
    return ', '.join(errors)


def print_errors(errors, verbosity):
    """Print the errors, and return the return code."""
    if errors:
        print errors
        return 2
    else:
        print 'All cool'
        return 0

def setup_logger(verbose):
    """Creates a logger, using the verbosity, and returns it."""
    logger = logging.getLogger()
    if verbose >= 3:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)        
    logger.addHandler(logging.StreamHandler())
    return logger

def main():
    """Main procedure for Azure monitor utility."""
    args = handle_args()

    logger = setup_logger(args.verbose)
    logger.debug('Converting publishsettings.')
    try:
        publishsettings = PublishSettings(args.psfile)
    except Exception, error:
        print 'Publishsettings file is not good'
        print error
        sys.exit(1)
    pem_path = publishsettings.write_pem()
    logger.debug('Pem file saved to temp file {0}'.format(pem_path))
    logger.debug('Azure sub id {0}'.format(publishsettings.sub_id))

    management = ServiceManagementService(
        subscription_id=publishsettings.sub_id,
        cert_file=pem_path)
    if args.all:
        errors = check_for_errors_all(management)
    else:
        errors = check_for_errors(management, args.hostname)
    logger.debug('Azure status retreived.')

    os.unlink(pem_path)
    logger.debug('Deleted pem.')

    ret_val = print_errors(errors, args.verbose)
    sys.exit(ret_val)

if __name__ == '__main__':
    main()
