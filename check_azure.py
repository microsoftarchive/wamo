#!/usr/bin/python

import argparse
import os
import sys
from azure.servicemanagement import ServiceManagementService
from azuremonitor.publishsettings import PublishSettings

def handle_args():
    parser = argparse.ArgumentParser(description='Check Azure.', epilog='(c) MS Open Tech')
    parser.add_argument('-p', '--publish-settings', required=True, 
                        help='.publishsettings file to authenticate with azure', dest='psfile')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    return parser.parse_args()

def check_for_errors(service):
    hosted_services = service.list_hosted_services()
    errors = []
    for hs in hosted_services:
        hosted_service = service.get_hosted_service_properties(hs.service_name, embed_detail=True)
        for deployment in hosted_service.deployments:
            if deployment.status != 'Running':
                errors.append('Hosted Service {}, Deployment {}, Status: {}'.format(
                        hosted_service.service_name, deployment.name, deployment.status))
            for role_inst in deployment.role_instance_list:
                if role_inst.power_state != 'Started':
                    errors.append('Hosted Service {}, Deployment {}, Role {}, Power: {}'.format(
                            hosted_service.service_name, deployment.name, role_inst.role_name, 
                            role_inst.power_state))
                if role_inst.instance_status != 'ReadyRole':
                    errors.append('Hosted Service {}, Deployment {}, Role {}, Status: {}'.format(
                            hosted_service.service_name, deployment.name, role_inst.role_name, 
                            role_inst.instance_status))
    return errors

def print_errors(errors, verbosity):
    if errors:
        if verbosity == 0:
            print 'Errors!'
        else:
            if len(errors) == 1:
                print errors[0]
            else:
                print 'Multiple errors'
                if verbosity >= 2:
                    for error in errors:
                        print error
        return 2
    else:
        print 'All cool'
        return 0

def main():
    args = handle_args()

    if args.verbose >= 3:
        print 'Converting publishsettings.'
    try:
        ps = PublishSettings(args.psfile)
    except Exception,e:
        print 'Publishsettings file is not good'
        print e
        sys.exit(1)
    pem_path = ps.write_pem()
    if args.verbose >= 3:
        print 'Pem file saved to temp file {}'.format(pem_path)
        print 'Azure sub id {}'.format(ps.sub_id)

    service = ServiceManagementService(subscription_id=ps.sub_id, cert_file=pem_path)
    errors = check_for_errors(service)
    if args.verbose >= 3:
        print 'Azure status retreived.'

    os.unlink(pem_path)
    if args.verbose >= 3:
        print 'Deleted pem.'

    rv = print_errors(errors, args.verbose)
    sys.exit(rv)

if __name__ == '__main__':
    main()
