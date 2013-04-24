#!/usr/bin/python

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
    parser.add_argument('-v', '--verbose', action='count', 
                        default=0, help='verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    return parser.parse_args()


def check_for_errors(service, hostname):
    """Check the status of hostname, and return a list of errors."""
    #hosted_services = service.list_hosted_services()
    errors = []
    try:
        service = service.get_hosted_service_properties(
            hostname,
            embed_detail=True)
    except azure.WindowsAzureMissingResourceError, error:
        errors.append('Hosted service {0} not found'.format(hostname))
        return errors
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
    return errors


def print_errors(errors, verbosity):
    """Print the errors, and return the return code."""
    if errors:
        print ', '.join(errors)
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

    service = ServiceManagementService(
        subscription_id=publishsettings.sub_id,
        cert_file=pem_path)
    errors = check_for_errors(service, args.hostname)
    logger.debug('Azure status retreived.')

    os.unlink(pem_path)
    logger.debug('Deleted pem.')

    ret_val = print_errors(errors, args.verbose)
    sys.exit(ret_val)

if __name__ == '__main__':
    main()
