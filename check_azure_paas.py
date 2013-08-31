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
#check_azure_paas.py: Azure paas monitor script

import argparse
import azure
from azure.servicemanagement import ServiceManagementService
from azure.storage.cloudstorageaccount import CloudStorageAccount
from azuremonitor.publishsettings import PublishSettings
from datetime import datetime
from datetime import timedelta
import logging
import os
import sys

primary_key = None       # pylint: disable-msg=C0103
logger = None            # pylint: disable-msg=C0103

COUNTERS     = {
    'cpupercentage'     : { 'help' : 'Get CPU Percentage',
                        'nagios_message'    : 'CPU Utilization is %s',
                        'unit'      : '%%',
                        'perf_counter'   :  
                            r'\Processor(_Total)\% Processor Time',
                        },          
    'asperrors'        : { 'help'      : 'Get ASP.NET errors per sec ',
                        'nagios_message'    : 'ASP.NET errors per sec is %s',
                        'unit'      : '',
                        'perf_counter'   :
                            r'\ASP.NET Applications(__Total__)\Errors Total/Sec',
                        'direction' : 'NA',
                        },          
    'asprequests'      : { 'help'      : 'Get ASP.NET requests per sec ',
                        'nagios_message'    : 'ASP.NET requests per sec is %s',
                        'unit'      : '',
                        r'perf_counter'   :  
                            r'\ASP.NET Applications(__Total__)\Requests/Sec',
                        'direction' : 'NA',
                        },          
    'requestsqueued'     : { 'help'      : 'Get ASP.NET requests queued',
                        'nagios_message'    : 'ASP.NET requests queued %s',
                        'unit'      : '',
                        r'perf_counter'   :  r'\ASP.NET\Requests Queued',
                        'direction' : 'NA',
                        },          
    'requestsrejected' : { 'help'      : 'Get ASP.NET requests rejected',
                        'nagios_message'    : 'ASP.NET requests rejected %s',
                        'unit'      : '',
                        r'perf_counter'   :  r'\ASP.NET\Requests Rejected',
                        'direction' : 'NA',
                        },          
    'availmemory'     : { 'help'      : 'Get available memory',
                        'nagios_message'    : 'Available memory %s ',
                        'unit'      : 'mb',
                        r'perf_counter'   :  r'\Memory\Available MBytes',
                        },          
    'wsbytespersec'     : { 'help'      : 'Get web service bytes per sec',
                        'unit'      : '',
                        r'perf_counter'   :  
                            r'\Web Service(_Total)\Bytes Total/Sec',
                        'direction' : 'NA',                  
                        'nagios_message'    : 'Web service bytes per sec %s',
                        },          
    'wsextpersec'     : { 'help'      : 'Get web service ext requests per sec',
                        'unit'      : '',
                        r'perf_counter'   :  
                            r'\Web Service(_Total)\ISAPI Extension Requests/sec',
                        'direction' : 'NA',
                        'nagios_message'    : 
                            'Web service ext requests per sec %s',
                        },          
    }


def is_within_range(nagstring, value):
    """check if the value is withing the nagios range string
    nagstring -- nagios range string 
    value  -- value to compare
    Returns true if within the range, else false
    """
    if not nagstring:
        return False
    import re
    #import operator
    first_float = r'(?P<first>(-?[0-9]+(\.[0-9]+)?))'
    second_float = r'(?P<second>(-?[0-9]+(\.[0-9]+)?))'
    actions = [ (r'^%s$' % first_float, 
                    lambda y: (value > float(y.group('first'))) or (value < 0)),
                (r'^%s:$' % first_float, 
                    lambda y: value < float(y.group('first'))),
                (r'^~:%s$' % first_float, 
                    lambda y: value > float(y.group('first'))),
                (r'^%s:%s$' % (first_float,second_float), 
                    lambda y: (value < float(y.group('first'))) or 
                    (value > float(y.group('second')))),
                (r'^@%s:%s$' % (first_float,second_float), 
                    lambda y: not((value < float(y.group('first'))) or 
                                  (value > float(y.group('second')))))]
    for regstr, func in actions:
        res = re.match(regstr, nagstring)
        if res: 
            return func(res)
    raise Exception('Improper warning/critical parameter format.')


def nagios_eval( rolename, result, warning, critical, 
                nagios_message, counter_name, unit='', verbosity = 0):
    """evaluate perf counters  with respect to warning and critical range 
    cloudservice_name -- azure cloud service. Used in message
    rolename -- web service rolename. Used in message
    result -- counter value
    warning -- nagios warning range string
    critical -- nagios critical range string
    nagios_message -- Nagios message 
    counter_name -- perf counter
    unit -- unit for the perf counter value
    verbosity -- nagios verbosity value
    Returns nagios code, and error message
    """

    if is_within_range(critical, result):
        prefix = 'CRITICAL: '
        code = 2
    elif is_within_range(warning, result):
        prefix = 'WARNING: '
        code = 1
    else:
        prefix = 'OK: '
        code = 0
    strresult = str(result)
    try:
        nagios_message = nagios_message % (strresult)
    except:
        pass
    if verbosity == 0:
        if code > 0:
            nagios_message = '%s:%s' % ( rolename, prefix)
        else:
            nagios_message = ''
    elif verbosity == 1:
        if code > 0:
            nagios_message = '%s:%s|%s=%s%s' % \
                ( rolename, prefix, counter_name, strresult,  unit or '')
        else:
            nagios_message = ''
    else:
        nagios_message = '%s:%s%s%s|%s=%s%s;warning=%s;critical=%s;' \
                % ( rolename, prefix, nagios_message, unit or '', counter_name, 
                   strresult,  unit or '', warning or '', critical or '')
    return code, nagios_message


def get_and_check_counter(counter, cloudservice_name, management,  
                          storageacct_name,  warning, critical, verbosity):
    """retrieve performance counter and evaluate with respect to warning and 
    critical range and return appropriate error message
    management - storagemanagement object
    storageacct_name -- storage account name
    cloudservice_name -- azure cloud service name. Used in message
    counter -- counter entry from COUNTERS list
    warning -- nagios warning range string
    critical -- nagios critical range string
    verbosity -- nagios verbosity value
    Returns nagios code and error message
    """

    global primary_key
    global logger

    try:
        logger.debug('Retrieve service object for ' + cloudservice_name)
        service = management.get_hosted_service_properties(
            cloudservice_name,
            embed_detail=True)
    except azure.WindowsAzureMissingResourceError, error:
        return 3, 'Hosted service {0} not found'.format(cloudservice_name)

    errors = []
    if not service.deployments:
        return 1, 'No deployments found'

    # find the production deployment among deployments 
    production_depl = None
    for depl in service.deployments:
        if depl.deployment_slot == 'Production':
            production_depl = depl
            break
    error_code_all = 0
    if production_depl:
        try:
            storage_account = CloudStorageAccount(storageacct_name, primary_key)
            table_service = storage_account.create_table_service()
            table_name = 'WAD'+ str(production_depl.private_id) + \
                            'PT'+ '1H' +'R'+'Table'
            error_code_all = 0
            for role in production_depl.role_list:
                role_clause = 'Role eq \''+ role.role_name + '\''
                # we use 2 hours earlier since some times no counters 
                # show up with 1 hour
                rngtime = (datetime.utcnow() - datetime.min) - \
                        timedelta(minutes = 120)
                partition_str = '0' + \
                    str(((rngtime.days * 24 * 60 * 60 + rngtime.seconds) 
                         * 1000 * 1000 + rngtime.microseconds)*10)
                partition_clause = 'PartitionKey ge \''+ partition_str +'\''
                counter_clause =  'CounterName eq \''+counter['perf_counter']+'\''
                filter_str = role_clause + ' and ' + \
                            partition_clause + ' and ' + counter_clause

                logger.debug('Checking Table: {0}, Filter: {1}'.format(
                        table_name, filter_str))
                results = table_service.query_entities(table_name=table_name, 
                                                       filter=filter_str)
                if len(results) != 0:
                    latest_result = results[len(results)-1]
                    error_code, error = nagios_eval(  role.role_name, 
                                                      latest_result.Total,
                                                      warning,
                                                      critical,
                                                      counter['nagios_message'],
                                                      counter['perf_counter'],
                                                      counter['unit'],
                                                      verbosity
                                                      )
                    if error_code > 0 or verbosity > 1:
                        error_code_all = max(error_code_all, error_code)
                        errors.append(error)
                else:
                    error_code_all = 3
                    errors.append('{1}, Critical: perf counter {2} not found:'
                                  .format(cloudservice_name,role.role_name, 
                                          counter['perf_counter']))
        except azure.WindowsAzureMissingResourceError, error:
            error_code_all = 3
            errors.append('System error - storage account: {0}, service:{1}'
                          .format(storageacct_name, cloudservice_name ))
    else:
        error_code_all = 3
        errors.append('No deployment found - storage account: {0}, service:{1}'
                      .format(storageacct_name, cloudservice_name))
    return  error_code_all, ', '.join(errors)


def handle_args():
    """Create the parser, parse the args, and return them."""
    parser = argparse.ArgumentParser(description='Check Azure PAAS Deployments',
                                     epilog='(c) MS Open Tech')
    parser.add_argument('cloudservice', 
                        help='Name of the cloud service to check')    
    parser.add_argument(
        '-s', '--storageact',
        required=True,
        help='Azure storage account where service counters are saved',
        dest='storageact')
    parser.add_argument(
        '-p', '--publish-settings',
        required=True,
        help='.publishsettings file to authenticate with azure',
        dest='psfile')
    if os.name == 'nt':
        parser.add_argument(
            '-f', '--certname',
            required=False,
            help='Cert authentication filename. needed on Windows',
            dest='cert')
    parser.add_argument('-a', '--all', action='store_true',
                        help='check all hosted cloud services, '\
                        'ignores cloudservice parameter')
    parser.add_argument('-w', '--warning', required=False, dest='warning',
                        help='Specify warning range')
    parser.add_argument('-c', '--critical', required=False, dest='critical',
                        help='Specify critical range')
    parser.add_argument('-k', '--key', required=False, dest='key',
                        help='Status/Counter to check')
    parser.add_argument('-v', '--verbose', action='count', 
                        default=0, help='verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    return parser.parse_args()


def setup_logger(verbose):
    """Creates a logger, using the verbosity, and returns it."""
    global logger
    logger = logging.getLogger()
    if verbose >= 3:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)        
    logger.addHandler(logging.StreamHandler())


def retrieve_keys(management, storageacct):
    """retrieve primary and secondary storage keys."""
    try:
        storage_keys = management.get_storage_account_keys(storageacct.lower())
        temp_primary_key  = storage_keys.storage_service_keys.primary
        temp_secondary_key = storage_keys.storage_service_keys.secondary
        return temp_primary_key, temp_secondary_key
    except azure.WindowsAzureError, error:
        global logger
        logger.debug(error)
        return None, None


def check_counter(management, cloudservice_name, args):
    """check azure cloudservice perf counter for warning and critical ranges
    management - storagemanagement object
    cloudservice_name -- azure cloud service name. Used in message
    args -- command parameters
    Returns nagios code and error message
    """
    global logger
    

    storageacct_name = args.storageact.lower()    
    verbosity = args.verbose
    if args.key:
        key = args.key.lower()
    else:
        return 3, 'key/performance counter missing'
    logger.debug('Checking ' + key + ' in ' + cloudservice_name)

    if key not in COUNTERS:
        return 3, 'Illegal key/performance counter'
    counter = COUNTERS[key]
    error_code, error = get_and_check_counter(counter, cloudservice_name, 
                                             management, storageacct_name,  
                                             args.warning, args.critical, 
                                             verbosity)
    return error_code, error 


def check_counter_all(management, args):
    """Check the counter in all cloud services, and return a list of errors."""
    global logger

    logger.debug('Retrieving all hosted services')
    hosted_services = management.list_hosted_services()
    error_code_all = 0
    errors = []
    if not hosted_services:
        error_code_all = 2
        errors.append('No hosted services found')
    for service in hosted_services:
        logger.debug('Checking counter in '+service.service_name)
        error_code, error = check_counter(management, 
                                          service.service_name, args)
        errors.append(' '.join(('{0}:'.format(service.service_name), error)))
        error_code_all = max (error_code_all, error_code)
    return error_code_all, '; '.join(errors)


def check_service(management, cloudservice, verbosity = 0):
    """Check the status of the cloud service, and return error."""
    errors = []
    error_code_all = 0

    try:
        service = management.get_hosted_service_properties(
            cloudservice,
            embed_detail=True)
    except azure.WindowsAzureMissingResourceError:
        error_code_all = 3
        errors.append('Hosted service {0} not found'.format(cloudservice))
        return ', '.join(errors)
    if service.hosted_service_properties.status != 'Created':
        error_code_all = 2        
        errors.append('Service status: {0}'
                      .format(service.hosted_service_properties.status))
    if not service.deployments:
        error_code_all = 2
        errors.append('No deployments found')
    for deployment in service.deployments:
        if deployment.status != 'Running':
            error_code = 2
            errors.append('Deployment status: {0}'
                          .format(deployment.status))
        else: 
            error_code = 0
            if verbosity > 0:
                errors.append('Deployment({1}), status: {0}'
                              .format(deployment.status, deployment.label))
            else:
                errors.append('All OK')

        if not deployment.role_instance_list:
            error_code = 2
            errors.append('No role instances found')
        for role_inst in deployment.role_instance_list:
            if role_inst.power_state != 'Started':
                error_code = 2
                errors.append('Power state: {0}'
                              .format(role_inst.power_state))
            if role_inst.instance_status != 'ReadyRole':
                error_code = 2
                errors.append('Role status: {0}'
                              .format(role_inst.instance_status))
        error_code_all = max (error_code_all, error_code)
    return error_code_all, ', '.join(errors)


def check_service_all(management, verbosity):
    """Check the status of all hosted services, and return a list of errors."""
    global logger

    logger.debug('Retrieving all hosted services')
    hosted_services = management.list_hosted_services()
    error_code_all = 0
    errors = []
    if not hosted_services:
        error_code_all = 1
        errors.append('No hosted services found')
    for service in hosted_services:
        logger.debug('Checking status of '+service.service_name)
        error_code, error = check_service(management, 
                                          service.service_name, verbosity)
        errors.append(' '.join(('{0}:'.format(service.service_name), error)))
        error_code_all = max (error_code_all, error_code)
    return error_code_all, '; '.join(errors)


def main():
    """Main procedure for Azure monitor utility."""
    global primary_key
    global logger
    
    args = handle_args()

    if not args.all and not args.cloudservice:
        print 'Cloudservice name missing'        
        sys.exit(3)

    setup_logger(args.verbose)
    logger.debug('Converting publishsettings.')
    try:
        publishsettings = PublishSettings(args.psfile)
    except Exception, error:
        print 'Publishsettings file is not good. Error %s' % error
        sys.exit(3)
    if os.name != 'nt':
        pem_path = publishsettings.write_pem()
        logger.debug('Pem file saved to temp file {0}'.format(pem_path))
        logger.debug('Azure sub id {0}'.format(publishsettings.sub_id))
        management = ServiceManagementService(
            subscription_id=publishsettings.sub_id,
            cert_file=pem_path)
    else:
        logger.debug('Using cert to instantiate ServiceManagement.')
        if args.cert:
            management = ServiceManagementService(
                publishsettings.sub_id,
                cert_file=args.cert)
        else:
            print 'Cert is missing. Required on Windows'
            sys.exit(3)

    if args.key != 'status' :
        logger.debug('Retrieving storage keys.')
        primary_key, _ = retrieve_keys(management, args.storageact)         
        if not primary_key:
            if os.name != 'nt':
                os.unlink(pem_path)
                logger.debug('Deleted pem.')
            print 'Invalid storage account or error retrieving storage keys'
            sys.exit(3)

    error = ''
    error_code = 0
    if args.all:
        if args.key == 'status':
            error_code, error = check_service_all(management, args.verbose)
        else:        
            error_code, error = check_counter_all(management, args)
    else:
        if args.key == 'status' :
            error_code, error = check_service(management, 
                                             args.cloudservice.lower(), 
                                             args.verbose)
        else:        
            error_code, error = check_counter(management, 
                                              args.cloudservice.lower(), 
                                              args)

    if os.name != 'nt':
        os.unlink(pem_path)
        logger.debug('Deleted pem.')

    if error_code == 0 and not error:
        error = 'All OK'
    print error
    sys.exit(error_code)


if __name__ == '__main__':
    main()
