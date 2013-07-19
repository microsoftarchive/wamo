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
#check_azure_storage.py: Azure storage monitor script

"""Contains the nagios azure storage plugin code."""

import argparse
import azure
from azure.storage.cloudstorageaccount import CloudStorageAccount
import logging
import os
from azuremonitor.publishsettings import PublishSettings
from azure.servicemanagement import ServiceManagementService
import sys
from datetime import datetime
from datetime import timedelta
import exceptions

logger = None            # pylint: disable-msg=C0103

COUNTERS     = {
    'ingress'         : { 'help' : 'Get Total Ingress',
                            'measure'   :  'TotalIngress',
                            'nagios_message' : 'Total incoming traffic %s',
                            'unit' : 'MB',
                            #'direction' : 'NA'
                            },          
    'egress'         : { 'help' : 'Get Total Engress',
                            'measure'   :  'TotalEgress',
                            'nagios_message' : 'Total outgoing traffic %s',
                            'unit' : 'MB',
                            #'direction' : 'NA'
                            },          
    'requests'         : { 'help' : 'Get total requests',
                            'measure'   :  'TotalRequests',
                            'nagios_message' : 'Total number of requests %s',
                            'unit' : '',
                            #'direction' : 'NA'
                            },      
    'billablerequests': { 'help' : 'Get Total billable requests',
                            'measure'   :  'TotalBillableRequests',
                            'nagios_message' : 
                                    'Total number of billable requests %s',
                            'unit' : '',
                            #'direction' : 'NA'
                            },      
    'availability': { 'help' : 'Get availability',
                            'measure'   :  'Availability',
                            'nagios_message' : 'Availability %s',
                            'unit' : '%',
                            #'direction' : 'NA',
                            },              
    'percentsuccess': { 'help' : 'Get percent success',
                            'measure'   :  'PercentSuccess',
                            'nagios_message' : 
                                'Successful requests out of total = %s',
                            'unit' : '%',
                            #'direction' : 'NA',
                            },      
    'e2elatency': { 'help' : 'Get E2E latency',
                            'measure'   :  'AverageE2ELatency',
                            'nagios_message' : 'End to end latency %s',
                            'unit' : 'ms',
                            #'direction' : 'NA'
                            },      
    'srvlatency': { 'help' : 'Get Avg server latency',
                            'measure'   :  'AverageServerLatency',
                            'nagios_message' : 'Server latency %s',
                            'unit' : 'ms',
                            #'direction' : 'NA'
                            },      
    'throttlingerr': { 'help' : 'Get percent throttling error',
                            'measure'   :  'PercentThrottlingError',
                            'nagios_message' : 'Throttling error %s',
                            'unit' : '%',
                            #'direction' : 'NA'
                            },      
    'timeouterr': { 'help' : 'Get percent timeout error',
                            'measure'   :  'PercentTimeoutError',
                            'nagios_message' : 'Timeout error %s',
                            'unit' : '%',
                            #'direction' : 'NA'
                            },      
    'srverror': { 'help' : 'Get percent server other error',
                            'measure'   :  'PercentServerOtherError',
                            'nagios_message' : 'Other server error %s',
                            'unit' : '%',
                            #'direction' : 'NA'
                            },      
    'clienterror': { 'help' : 'Get percent client other error',
                            'measure'   :  'PercentClientOtherError',
                            'nagios_message' : 'Client error %s',
                            'unit' : '%',
                            #'direction' : 'NA'
                            },      
    'anonclienterror': { 'help' : 'Get anon client other error',
                            'measure'   :  'AnonymousClientOtherError',
                            'nagios_message' : 'Anonymous client error %s',
                            'unit' : '%',
                            #'direction' : 'NA'
                            },       
    }


def property_value(row, prop):
    """Get the value of the row/object property specified by prop."""
    return {
       'TotalIngress': row.TotalIngress,
       'TotalEgress': row.TotalEgress,
       'TotalRequests': row.TotalRequests,
       'TotalBillableRequests': row.TotalBillableRequests,
       'Availability': row.Availability,
       'PercentSuccess': row.PercentSuccess,
       'AverageE2ELatency': row.AverageE2ELatency,
       'AverageServerLatency': row.AverageServerLatency,
       'PercentThrottlingError': row.PercentThrottlingError,
       'PercentTimeoutError': row.PercentTimeoutError,
       'PercentServerOtherError': row.PercentServerOtherError,
       'PercentClientOtherError': row.PercentClientOtherError,
       'AnonymousClientOtherError': row.AnonymousClientOtherError       
    }[prop]


def handle_args():
    """Create the parser, parse the args, and return them."""
    parser = argparse.ArgumentParser(description='Check Azure Storage',
                                     epilog='(c) MS Open Tech')
    parser.add_argument('storageact', 
                        help='Storage account name to check')
    parser.add_argument(
        '-p', '--publish-settings',
        required=True,
        help='.publishsettings file to authenticate with azure',
        dest='psfile')
    if os.name == 'nt':
        parser.add_argument(
            '-f', '--certname',
            required=False,
            help='cert authentication with azure. needed on Windows',
            dest='cert')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--table', action='store_const', 
                       help="Check table service",
                        const='table', dest='type')
    group.add_argument('--blob', action='store_const',  
                       help="Check blob service",
                        const='blob', dest='type')
    group.add_argument('--queue', action='store_const',  
                       help="Check queue service",
                        const='queue', dest='type')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--tx', action='store_const', const='tx', 
                       dest='subtype', help="Check transaction metrics")
    group.add_argument('--cap', action='store_const', 
                        const='cap', dest='subtype',  
                        help="Check capacity metrics. Applies only to -blob")

    parser.add_argument('-a', '--all', action='store_true',
                        help='Check all storage accounts, ignores storageact')

    parser.add_argument('-w', '--warning', required=False, dest='warning',
                        help='Specify warning threshold')
    parser.add_argument('-c', '--critical', required=False, dest='critical',
                        help='Specify critical threshold')
    parser.add_argument('-k', '--key', required=False, dest='key',
                        help='Status/Counter to check')
    parser.add_argument('-v', '--verbose', action='count', 
                        default=0, help='verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    return parser.parse_args()


def eval_counter_for_nagios(row, counter, warning, critical, verbosity):
    """get the metric  for the key and check within the nagios range
    row - metric object
    counter - counter from COUNTERS dict
    warning -- Nagios warning range
    critical -- Nagios critical range
    """
    prop = counter['measure']    
    val = property_value(row, prop)
    unit = counter['unit']

    return nagios_eval(val, warning, critical, counter['nagios_message'], 
                       unit, verbosity)


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


def nagios_eval(result, warning, critical, nagios_message, unit='', 
                verbosity = 0):
    """evaluate result with respect to warning and critical range and 
        return appropriate error message
    result -- counter value
    warning -- nagios warning range string
    critical -- nagios critical range string
    nagios_message -- Nagios message 
    unit -- unit for the perf counter value
    verbosity -- nagios verbosity value
    Returns nagios code, and error message
    """

    if is_within_range(critical, result):
        prefix = 'CRITICAL:'
        code = 2
    elif is_within_range(warning, result):
        prefix = 'WARNING:'
        code = 1
    else:
        prefix = 'OK:'
        code = 0
    strresult = str(result)
    if verbosity == 0:
        if code > 0:
            nagios_message = '%s' % prefix
        else:
            nagios_message = ''
    elif verbosity == 1:
        if code > 0:
            nagios_message = nagios_message % (strresult)
            nagios_message = '%s:%s=%s %s' % ( prefix, nagios_message, 
                                              strresult,  unit or '')
        else:
            nagios_message = ''
    else:
        nagios_message = nagios_message % (strresult)
        nagios_message = '%s%s%s,warning=%s,critical=%s,'\
         % ( prefix, nagios_message, unit or '', warning or '', critical or '')
    return code, nagios_message


def setup_logger(verbose):
    """Creates a logger, using the verbosity, and returns it."""
    global logger
    logger = logging.getLogger()
    if verbose >= 3:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)        
    logger.addHandler(logging.StreamHandler())


def retrieve_keys(management, storageacct_name):
    """retrieve primary and secondary keys."""
    try:
        storage_keys = management.get_storage_account_keys(storageacct_name)
        primary_key  = storage_keys.storage_service_keys.primary
        secondary_key = storage_keys.storage_service_keys.secondary
        return primary_key, secondary_key
    except:
        return None, None


def check_storagecap_errors(table_service):
    """Check storage capacity errors supported only for blob
    table_service -- table service where metric are stored
    warning - Nagios warning level 
    critical - Nagios critical level 
    """
    
    latest_utcime = datetime.utcnow()
    latestday = (latest_utcime - timedelta(days=1)).strftime('%Y%m%dT0000')
    recentday_partitionkey = 'PartitionKey ge \'%s\'' % latestday
    table_name = '$MetricsCapacityBlob'
    try:
        rows = table_service.query_entities(table_name=table_name, 
                                            filter=recentday_partitionkey)        
        if len(rows) > 1:
            row = rows[len(rows)-1]
            msg_one = '{0}:{{Capacity:{1}, ContainerCount:{2}, '\
                'ObjectCount:{3}}}'.format(row.RowKey, row.Capacity, 
                                           row.ContainerCount, row.ObjectCount)
            row = rows[len(rows)-2]
            msg_two = '{0}:{{Capacity:{1}, ContainerCount:{2},'\
                ' ObjectCount:{3}}}'.format(row.RowKey, 
                                            row.Capacity, 
                                            row.ContainerCount, 
                                            row.ObjectCount)
            return 0, '{0},{1}'.format(msg_one, msg_two)
        else:
            return 3, 'Capacity data not found'
    except azure.WindowsAzureMissingResourceError:
        return 3, 'Capacity table not found'
    except:
        return 3, 'Internal error'


def check_storagetx_errors(table_service, storage_type, key, warning, 
                           critical, verbosity):
    """Check storage transaction errors 
    table_service -- table service where metric are stored
    type -- blob/queue/table
    key - needed only for transaction metric
    warning - Nagios warning level 
    critical - Nagios critical level 
    """

    errors = []
    try:
        latest_utcime = datetime.utcnow()
        latest_hour = (latest_utcime-timedelta(hours=2)).strftime('%Y%m%dT%H00')
        recenthour_partitionkey = 'PartitionKey ge \'%s\'' % latest_hour

        storage_type = storage_type.lower()

        if storage_type == 'blob':
            table_name = '$MetricsTransactionsBlob'
        elif storage_type == 'table':
            table_name = '$MetricsTransactionsTable'
        else:
            table_name = '$MetricsTransactionsQueue'
        rows = table_service.query_entities(table_name = table_name, 
                                            filter = recenthour_partitionkey)

        if len(rows) > 0:
            row = rows[len(rows)-1]
        else:
            return 3, 'Performance data not available'

        current_counters = {}
        
        if key == 'all':
            # for inspecting all keys, we can't use critical or warning levels
            current_counters = COUNTERS
            warning = None
            critical = None
        else:
            current_counters[key] = COUNTERS[key]

        error_code_all = 0
        errors = []
        for temp_key in current_counters:
            counter = COUNTERS[temp_key]
            error_code, error = eval_counter_for_nagios(row, counter, warning, 
                                                        critical, verbosity )
            error_code_all = max(error_code_all, error_code)
            errors.append(error)        
    except azure.WindowsAzureMissingResourceError, error:
        error_code = 3
        errors.append('Performance table not found.')
    except exceptions.KeyError, error:
        error_code = 3
        errors.append('Specified key was not found.')
    return error_code, '; '.join(errors)


def check_storage_errors_all(management, storage_type, subtype, key, warning, 
                             critical, verbosity):
    """Check storage errors for the metric given by key
    management -- service management object

    type -- blob/queue/table
    subtype - tx/cap (transactions or capacity)
    key - needed only for transaction metric
    warning - Nagios warning level 
    warning - Nagios critical level 
    """
    error_code_all = 0
    errors = []
    storage_accounts = management.list_storage_accounts()
    for storage_account in storage_accounts:
        error_code, error = check_storage_errors(management, 
                                                 storage_account.service_name, 
                                                 storage_type, subtype, 
                                                 key, 
                                                 warning, 
                                                 critical, 
                                                 verbosity)
        error_code_all = max(error_code_all, error_code)
        errors.append(storage_account.service_name + ':{'+error + '}')
    return error_code_all, ', '.join(errors)


def check_storage_errors(management, storageact_name, storage_type, subtype, 
                         key, warning, critical, verbosity):
    """Check storage errors for the metric given by key
    management -- service management object
    storageact_name -- storage account name
    storage_type -- blob/queue/table
    subtype - tx/cap (transactions or capacity)
    key - needed only for transaction metric
    warning - Nagios warning level 
    warning - Nagios critical level 
    """
    primary_key, _ = retrieve_keys(management, storageact_name.lower())         
    if not primary_key:
        return 3, 'Error retrieving storage keys'

    storage_account = CloudStorageAccount(storageact_name.lower(), primary_key)
    if not storage_account:
        return 3, 'Error retrieving storage account'

    try:
        table_service = storage_account.create_table_service()
    except:
        return 3, 'System error in creating table service'
    if subtype == 'cap':
        if storage_type == 'blob':
            return check_storagecap_errors(table_service)
        else:
            return 3, 'Capacity metrics not supported for tables/queues' 
    else:
        if (not key):
            return 3, 'Key missing'
        return check_storagetx_errors(table_service, storage_type, key.lower(), 
                                      warning, critical, verbosity)


def main():
    """Main procedure for Azure monitor utility."""
    global logger

    error = ''
    error_code = 0
    args = handle_args()

    if not args.all and not args.storageact:
        print 'Storage acct name missing'        
        sys.exit(3)

    setup_logger(args.verbose)
    logger.debug('Converting publishsettings.')
    try:
        publishsettings = PublishSettings(args.psfile)
    except error:
        print 'Publishsettings file is not good. Error %s' % error
        sys.exit(1)
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

    if args.subtype != 'cap':
        if not args.key:
            print 'Key is required for storage transactions.'
            sys.exit(3)
            
    if args.all:
        error_code, error = check_storage_errors_all(management,  
                                                     args.type, 
                                                     args.subtype, 
                                                     args.key, 
                                                     args.warning, 
                                                     args.critical, 
                                                     args.verbose)
    else:
        error_code, error = check_storage_errors(management, 
                                                 args.storageact.lower(), 
                                                 args.type, args.subtype, 
                                                 args.key, 
                                                 args.warning, 
                                                 args.critical, 
                                                 args.verbose)

    if os.name != 'nt':
        os.unlink(pem_path)
        logger.debug('Deleted pem.')

    if error_code == 0 and not error:
        error = 'All OK'
    print error
    sys.exit(error_code)


if __name__ == '__main__':
    main()
