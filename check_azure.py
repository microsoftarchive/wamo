#!/usr/bin/python

import argparse
import OpenSSL.crypto
import azure.servicemanagement
import base64
import os
import sys
import tempfile
import xml.dom.minidom

def pkcs12_to_pem(pkcs12_buffer):
    pkcs12 = OpenSSL.crypto.load_pkcs12(pkcs12_buffer)
    cert = pkcs12.get_certificate()
    private_key = pkcs12.get_privatekey()
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    (pem_fd, pem_path) = tempfile.mkstemp()
    pem_file = os.fdopen(pem_fd, 'w')
    pem_file.write(pkey_pem)
    pem_file.write(cert_pem)
    pem_file.close
    return pem_path

def publishsettings_handler(ps):
    ps_doc = xml.dom.minidom.parse(ps)
    publish_data = ps_doc.getElementsByTagName('PublishData')[0]
    publish_profile = publish_data.getElementsByTagName('PublishProfile')[0]
    pkcs12_b64 = publish_profile.getAttribute('ManagementCertificate')
    sub = publish_profile.getElementsByTagName('Subscription')[0]
    sub_id = sub.getAttribute('Id')
    pkcs12_buf = base64.b64decode(pkcs12_b64)
    return (sub_id, pkcs12_buf)

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
    (sub_id, pkcs12_buf) = publishsettings_handler(args.psfile)
    pem_path = pkcs12_to_pem(pkcs12_buf)
    if args.verbose >= 3:
        print 'Pem file saved to temp file {}'.format(pem_path)
        print 'Azure sub id {}'.format(sub_id)

    service = azure.servicemanagement.ServiceManagementService(subscription_id=sub_id, 
                                                               cert_file=pem_path)
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
