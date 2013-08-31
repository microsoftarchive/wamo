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
#check_azure_compute.py: Azure active director monitor script


import argparse
import ast
import json
import logging
import os
import shutil
import sys
import tempfile
import urllib
import urllib2

primary_key = None   # pylint: disable-msg=C0103
secondary_key = None # pylint: disable-msg=C0103

token = None          # pylint: disable-msg=C0103
token_type = None     # pylint: disable-msg=C0103
tenant_domain = None  # pylint: disable-msg=C0103
logger = None         # pylint: disable-msg=C0103

BASEURL = 'https://graph.windows.net/%s/%s?api-version=2013-04-05'
BASEURLONEPARAM = 'https://graph.windows.net/%s/%s?$filter='\
                  'displayName%%20eq%%20\'%s\'&api-version=2013-04-05'
DELTAGROUPQUERYURL = 'https://graph.windows.net/%s/directoryObjects?'\
                     'api-version=2013-04-05&$filter=isof(\'Microsoft.'\
                     'WindowsAzure.ActiveDirectory.Group\')&deltaLink=%s'
DELTAGROUPUSERQUERYURL = 'https://graph.windows.net/%s/directoryObjects?'\
                         'api-version=2013-04-05&$filter=isof(\'Microsoft.'\
                         'WindowsAzure.ActiveDirectory.User\')%%20or%%20isof'\
                         '(\'Microsoft.WindowsAzure.ActiveDirectory.Group\')&'\
                         'deltaLink=%s'
DELTAUSERQUERYURL = 'https://graph.windows.net/%s/directoryObjects?api-version'\
                    '=2013-04-05&$filter=isof(\'Microsoft.WindowsAzure.'\
                    'ActiveDirectory.User\')&deltaLink=%s'
HOST = 'graph.windows.net'


def analyze_group(group, verbosity, error_level):
    """analyze AD group object
    group -- group object to be analyzed
    verbosity - NAGIOS verbosity level - ignored
    error_level - ignored 
    Returns the Nagios error code (always 0) and error message (group defn)
    """
    return 0, '{name:%s, description:%s, objectId:%s, Security enabled:%r, '\
              'Dirsync enabled:%r, mail enabled:%r}' % (group['displayName'],
                                                        group['description'],
                                                        group['objectId'],
                                                        group['securityEnabled'],
                                                        group['dirSyncEnabled'],
                                                        group['mailEnabled'])


def analyze_user(user, verbosity, error_level):
    """analyze AD user object
    user -- user object to be analyzed
    verbosity - NAGIOS verbosity level  - ignored 
    error_level - ignored 
    Returns the Nagios error code (always 0) and error message (user defn)
    """
    return 0, '{principal name:%s, displayName: %s, objectId:%s, given name:%s,'\
              ' surname:%s, mail nickname:%s}' % (user['userPrincipalName'], 
                                                  user['displayName'],
                                                  user['objectId'], 
                                                  user['givenName'], 
                                                  user['surname'],
                                                  user['mailNickname'])

def analyze_user_delta(content, verbosity, error_level):
    """analyze user differential query data
    content -- output of deltalink command
    verbosity - NAGIOS verbosity level 
    error_level - value of warning-on-change or error-on-change
    Returns the Nagios error code and error message
    """
    change_entries = content['value']
    user_deleted_entries = 0
    user_change_entries = 0
    errors = []
    error_code_all = 0
    for change_entry in change_entries:
        error_code = 0
        if change_entry['odata.type'] == \
                    'Microsoft.WindowsAzure.ActiveDirectory.User':
            if 'aad.isDeleted' in change_entry:
                if change_entry['objectType'] == 'User':
                    user_deleted_entries += 1
                    error_code = error_level
                    error = 'User %s deleted' % \
                            change_entry['aad.originalUserPrincipalName']
            else:
                user_change_entries += 1
                error_code = error_level
                error = 'User %s added or changed' % \
                            change_entry['userPrincipalName']
        if error_code > 0:        
            error_code_all = max(error_code_all, error_code)
            errors.append(error)
    if verbosity > 0:        
        return error_code_all, ','.join(errors)
    else:
        message = ''
        if user_deleted_entries > 0:
            message =  message + '%d users deleted. ' % user_deleted_entries
        if user_change_entries > 0:
            message = message + ' %d users changed/added' % user_change_entries
        return error_code_all, message

    
def get_group_displayname(group_id):    
    """returns display name of a group
    group_id -- objectId of an AAD group
    Returns the display name of the AAD group
    """
    global tenant_domain
    url = BASEURLONEPARAM % (tenant_domain, 'groups', group_id)
    error_code, content = get_from_aad(url)
    if error_code == 0:
        return content['displayName']
    else:
        return group_id


def get_user_displayname(user_id):
    """returns display name of a user
    user_id -- objectId of an AAD user
    Returns the display name of the AAD user
    """
    global tenant_domain
    url = BASEURLONEPARAM % (tenant_domain, 'users', user_id)
    error_code, content = get_from_aad(url)
    if error_code == 0:
        return content['userPrincipalName']
    else:
        return user_id


def analyze_group_delta(content, verbosity, error_level):
    """analyze group differential query data
    content -- output of deltalink command
    verbosity - NAGIOS verbosity level 
    error_level - value of warning-on-change or error-on-change
    Returns the Nagios error code and error message
    """
    change_entries = content['value']
    group_deleted_entries = 0
    group_change_entries = 0
    groups_deleted_from_groups = 0
    groups_added_to_groups = 0
    errors = []
    error_code_all = 0
    for change_entry in change_entries:
        error_code = 0
        if change_entry['odata.type'] == \
                'Microsoft.WindowsAzure.ActiveDirectory.Group':
            if 'aad.isDeleted' in change_entry:
                if change_entry['objectType'] == 'Group':
                    group_deleted_entries += 1
                    error_code = error_level
                    if verbosity > 0:
                        error = 'Group %s deleted' % change_entry['objectId']
            else:
                group_change_entries += 1
                error_code = error_level
                if verbosity > 0:
                    error = 'Group %s added or changed' % \
                            change_entry['displayName']
        elif change_entry['odata.type'] == \
                'Microsoft.WindowsAzure.ActiveDirectory.DirectoryLinkChange':
            if 'aad.isDeleted' in change_entry:
                error_code = error_level  
                if change_entry['targetObjectType'] == 'Group':
                    groups_deleted_from_groups += 1
                    if verbosity > 0:
                        group_name = get_group_displayname(change_entry
                                                           ['sourceObjectId'])
                        error = 'Group %s deleted from group %s' % \
                                    (change_entry['targetObjectId'], group_name)
            elif 'associationType' in change_entry:
                if change_entry['associationType'] == 'Member':
                    error_code = error_level
                    if change_entry['targetObjectType'] == 'Group':
                        groups_added_to_groups += 1
                        if verbosity > 0:
                            added_group_name = get_group_displayname \
                                                (change_entry['targetObjectId'])
                            group_name = get_group_displayname \
                                            (change_entry['sourceObjectId']) 
                            error = 'Group %s added to group %s' % \
                                        (added_group_name, group_name)
                    elif change_entry['targetObjectType'] == 'User':
                        if verbosity > 0:
                            added_username = get_user_displayname \
                                        (change_entry['targetObjectId'])
                            group_name = get_group_displayname \
                                        (change_entry['sourceObjectId'])
                            error = 'User %s added to group %s' % \
                                        (added_username, group_name)

        if error_code > 0:        
            error_code_all = max(error_code_all, error_code)
            errors.append(error)
    if verbosity > 0:        
        return error_code_all, ', '.join(errors)
    else:
        message = ''
        if groups_deleted_from_groups > 0:
            message = message + '%d groups deleted from groups. ' \
                                % groups_deleted_from_groups
        if groups_added_to_groups > 0:
            message = message + '%d groups added to groups. ' \
                                % groups_deleted_from_groups
        if group_deleted_entries > 0:
            message = message + '%d groups deleted. ' \
                                % group_deleted_entries
        if group_change_entries > 0:
            message = message + '%d groups added/changed. ' \
                                % group_change_entries
        return error_code_all, message


def analyze_groupuser_delta(content, verbosity, error_level):
    """analyze user and group differential query data. 
    content -- output of deltalink command
    verbosity - NAGIOS verbosity level 
    error_level - value of warning-on-change or error-on-change
    Returns the Nagios error code and error message
    """
    change_entries = content['value']
    group_deleted_entries = 0   
    user_deleted_entries = 0
    group_change_entries = 0
    user_change_entries = 0
    users_deleted_from_groups = 0
    groups_deleted_from_groups = 0
    users_added_to_groups = 0
    groups_added_to_groups = 0
    errors = []
    error_code_all = 0
    for change_entry in change_entries:
        error_code = 0
        error = ''
        if change_entry['odata.type'] ==  \
                'Microsoft.WindowsAzure.ActiveDirectory.DirectoryLinkChange':
            if 'aad.isDeleted' in change_entry:
                error_code = error_level  
                if change_entry['targetObjectType'] == 'User':
                    users_deleted_from_groups += 1
                    if verbosity > 0:
                        group_name = \
                            get_group_displayname(change_entry['sourceObjectId'])
                        error = 'User %s deleted from group %s' \
                                % (change_entry['targetObjectId'], group_name)
                elif change_entry['targetObjectType'] == 'Group':
                    groups_deleted_from_groups += 1
                    if verbosity > 0:
                        group_name = get_group_displayname \
                                (change_entry['sourceObjectId'])
                        error = 'Group %s deleted from group %s' % \
                                    (change_entry['targetObjectId'], group_name)
            elif 'associationType' in change_entry:
                if change_entry['associationType'] == 'Member':
                    error_code = error_level
                    if change_entry['targetObjectType'] == 'User':
                        users_added_to_groups += 1
                        if verbosity > 0:
                            username = get_user_displayname\
                                            (change_entry['targetObjectId'])
                            group_name = get_group_displayname\
                                            (change_entry['sourceObjectId'])
                            error = 'User %s added to group %s' % \
                                            (username, group_name)
                    elif change_entry['targetObjectType'] == 'Group':
                        groups_added_to_groups += 1
                        if verbosity > 0:
                            added_group_name = get_group_displayname \
                                            (change_entry['targetObjectId'])
                            group_name = get_group_displayname\
                                            (change_entry['sourceObjectId'])
                            error = 'Group %s added to group %s' % \
                                            (added_group_name, group_name)
        elif change_entry['odata.type'] == \
                'Microsoft.WindowsAzure.ActiveDirectory.Group':
            error_code = error_level
            if 'aad.isDeleted' in change_entry:
                if change_entry['objectType'] == 'Group':
                    group_deleted_entries += 1
                    if verbosity > 0:
                        error = 'Group %s deleted' % change_entry['objectId']
            else:
                group_change_entries += 1
                error = 'Group %s added or changed' % \
                        change_entry['displayName']
        elif change_entry['odata.type'] == \
                'Microsoft.WindowsAzure.ActiveDirectory.User':
            if 'aad.isDeleted' in change_entry:
                if change_entry['objectType'] == 'User':
                    user_deleted_entries += 1
                    error_code = error_level
                    if verbosity > 0:
                        error = 'User %s deleted' % \
                                change_entry['aad.originalUserPrincipalName']
            else:
                user_change_entries += 1
                error_code = error_level
                error = 'User %s added or changed' % change_entry['displayName']
        if error_code > 0:        
            error_code_all = max(error_code_all, error_code)
            errors.append(error)

    if verbosity > 0:        
        return error_code_all, ','.join(errors)
    else:
        message = ''
        if groups_deleted_from_groups + users_deleted_from_groups > 0:
            message = message + '%d groups and %d users deleted from groups. '\
                    % (groups_deleted_from_groups, users_deleted_from_groups)
        if groups_added_to_groups + users_added_to_groups > 0:
            message = message + '%d groups and %d users added to groups. ' \
                    % (groups_added_to_groups, users_added_to_groups)
        if group_deleted_entries > 0 :
            message = message + '%d groups deleted. ' % group_deleted_entries
        if user_deleted_entries > 0 :
            message = message + '%d users deleted. ' % user_deleted_entries
        if group_change_entries > 0:
            message = message + '%d groups added/changed. ' % group_change_entries
        if user_change_entries > 0:
            message = message + '%d users added/changed. ' % user_change_entries
        return error_code_all, message
    

APIS     = {
    'listusers'              : { 'help' : 'Get all users',
                            'type'      : 'noparam',
                            'url'       :  BASEURL,
                            'entity'    : 'users',
                            'size'      : 'multiple',
                            'analyzefn'   : analyze_user
                            },           
    'listuser'              : { 'help' : 'Get one users',
                            'type'      : 'oneparam',
                            'url'       :  BASEURLONEPARAM,
                            'entity'    : 'users',
                            'size'      : 'multiple',
                            'analyzefn'   : analyze_user
                            },
    'listgroups'              : { 'help' : 'Get all groups',
                            'type'      : 'noparam',
                            'entity'    : 'groups',
                            'url'       :  BASEURL,
                            'size'      : 'multiple',
                            'analyzefn'   : analyze_group
                            },           
    'listgroup'              : { 'help' : 'Get one group',
                            'type'      : 'oneparam',
                            'url'       :  BASEURLONEPARAM,
                            'entity'    : 'groups',
                            'size'      : 'multiple',
                            'analyzefn'   : analyze_group
                            },
    'groupsdelta'              : { 'help' : 'Get one group',
                            'type'      : 'delta',
                            'url'       :  DELTAGROUPQUERYURL,
                            'size'      : 'single',
                            'analyzefn'   : analyze_group_delta
                            },
    'usersdelta'              : { 'help' : 'Get one group',
                            'type'      : 'delta',
                            'url'       :  DELTAUSERQUERYURL,
                            'size'      : 'single',
                            'analyzefn'   : analyze_user_delta
                            },
    'groupsusersdelta'       : { 'help' : 'Get one group',
                            'type'      : 'delta',
                            'url'       :  DELTAGROUPUSERQUERYURL,
                            'size'      : 'single',
                            'analyzefn'   : analyze_groupuser_delta
                            },
}


def property_value(row, prop):
    """gets a property value of a given object
    row -- object
    property - property name 
    Returns the value of the specified property
    """
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
    parser = argparse.ArgumentParser(description='Check Azure Active Directory',
                                     epilog='(c) MS Open Tech')
    parser.add_argument('domain', help='Specify Azure Active Directory domain')
    parser.add_argument(
        '-c', '--clientid',
        required=True,
        help='Specify Azure AD client id',
        dest='clientid')
    parser.add_argument(
        '-s', '--secret',
        required=True,
        help='Specify Azure AD secret used for programmatic access',
        dest='secret')

    parser.add_argument(
        '-p', '--param',
        required=False,
        help='param: user name or group name depending on command',
        dest='param')

    parser.add_argument(
        '-k', '--key',
        required=True,
        help='key - Key used to invoke specific API or get status of Azure AD',
        dest='key')

    parser.add_argument(
        '-t', '--tempdir',
        required=False,
        help='Temporary directory to save intermediate files',
        dest='tempdir')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--warn-on-change', action='store_const', const=1,
                       dest='level',
                       help='Change in users, groups, or membership to be flagged as warning',
                       default=0)
    group.add_argument('--error-on-change', action='store_const', const=2,
                       dest='level',
                       help='Change  users, groups, or membership to be flagged as error',
                       default=0)

    parser.add_argument('-v', '--verbose', action='count', 
                        default=0, help='Verbosity')
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


def get_from_aad( url):
    """executes an HTTP get request with auth tokens
    url - AAD endpoint
    Returns the results from HTTP requsest
    """
    global token
    global token_type
    global HOST
    headers = { 'Authorization' : token_type + ' ' + token,  
               'Accept':'application/json;odata=minimalmetadata', 
                'Content-Type':'application/json;odata=minimalmetadata',
                'Prefer':'return-content', 'Host':HOST}
    try:
        req = urllib2.Request( url, None, headers)
        response = urllib2.urlopen(req)
        content = response.read()  
        content_dict = json.loads(content)
        return 0, content_dict
    except urllib2.HTTPError as e:
        error = 'Http error code: %d' % e.code
    except urllib2.URLError as e:
        error = 'Url error code: %s' % e.reason[0]
    return 3, {'Error':error}


def get_deltalink_url(key, mytempdir):
    """gets the deltalink url 
    key - keys representing various commands from the COUNTERS list
    """
    deltalinks = {}
    deltalink_url = None
    global logger
    try:
        mytempdir = get_plugin_tempdir(mytempdir)
        if mytempdir is None:
            logger.error('Error. No temp dir path found for saving deltalinks file')
            return None, {}
        with open(mytempdir + '/azure_ad.dat','r+') as deltalink_file: 
            deltalinks_txt = deltalink_file.read()
            deltalinks = json.loads(deltalinks_txt)
            if key in deltalinks:
                deltalink_url = deltalinks[key] 
            deltalink_file.close()
            return deltalink_url, deltalinks
    except IOError:
        logger.error ('Error opening/reading temp file.')
        return None, {}

         
def check_aad_errors_for_simpleapi(api, args):
    """returns aad errors for ListUser(s) and ListGroup(s) commands
    api - command requested
    args - program options/switches
    returns NAGIOS error_code and NAGIOS output
    """
    url =  api['url']
    if api['type'] == 'oneparam':
        if args.param:
            escaped_param = urllib.quote(args.param)
            url = url % (args.domain, api['entity'], escaped_param)
        else:
            return 3, 'Command parameter value (-p) missing'
    else:
        url = url % (args.domain, api['entity'])
    error_code, content = get_from_aad(url)         
    errors = []
    if error_code == 0:
        if api['size'] == 'single':
            error_code, error =  api['analyzefn'](content['value'], 
                                                  args.verbose, 
                                                  args.level)
            errors.append(error)
        elif api['size'] == 'multiple':
			if not content['value']:
				error_code = 1
				errors.append("No data")
			else:				
				for val in content['value']:
					temp_error_code, error = api['analyzefn'](val, 
														 args.verbose, 
														 args.level)  
					error_code = max(error_code, temp_error_code)
					errors.append(error)
        return error_code, ', '.join(errors)      
    else:
        return error_code, content             

def check_aad_errors_for_deltaapi(api, args):
    """returns azure active director errors (for DeltaUsers, DeltaGroups, 
    ListGroupUsers commands)
    api - command requested
    args - program options/switches
    returns NAGIOS error_code and NAGIOS output
    """
    global logger
    found_deltalink = False
    url = api['url'] % (args.domain, '')
    deltalink_url, deltalinks = get_deltalink_url(args.key, args.tempdir)
    if deltalink_url:
        found_deltalink = True
        url = deltalink_url

    done = False
    error_code_all = 0
    errors = []
    while not done:
        error_code, content = get_from_aad( url)
        if error_code == 0:
            if not content['value'] or content['value'] == '[]':
                logger.debug('No changes')
            else:
                if not found_deltalink:
                    logger.debug('Initial enumeration')
                else:
                    error_code, error =  api['analyzefn'](content, 
                                                          args.verbose, 
                                                          args.level)
                    if error_code != 0:
                        error_code_all = max(error_code_all, error_code)
                    errors.append(error)
            if 'aad.nextLink' in content:
                url = content['aad.nextLink'] + '&api-version=2013-04-05'
            elif 'aad.deltaLink' in content:
                done = True
                deltalink_url = content['aad.deltaLink'] + \
                                        '&api-version=2013-04-05'
                error_code, error = update_deltalinks(deltalinks, 
                                                      deltalink_url, 
                                                      args.key,
                                                      args.tempdir)                
                if error_code != 0:
                    error_code_all = max(error_code_all, error_code)
                    errors.append(error)
        else:
            error_code_all = 3
            errors.append('Error executing get request %s' % url)
            done = True
                
    return error_code_all, ','.join(errors)


def check_aad_errors( args):
    """returns aad errors for aad requests
    args - command input
    returns NAGIOS error_code and NAGIOS output
    """
    global APIS
    if args.key.lower() not in APIS:
        return 3, 'Illegal API: %s not supported' % args.key
    api = APIS[args.key.lower()]
    if api['type'] == 'oneparam' or api['type'] == 'noparam':
        return check_aad_errors_for_simpleapi(api, args)
    else:
        return check_aad_errors_for_deltaapi(api, args)


def get_plugin_tempdir(mytempdir):
    """If mytempdir is not set, set to a save directory for saving state."""
    if mytempdir:
        return mytempdir
    if os.name != 'nt':
        nag_temppaths = ['/var/log/nagios', '/var/lib/nagios3']
    else:
        nag_temppaths = [tempfile.gettempdir()]
    for path in nag_temppaths:
        if os.path.isdir(path):
            return path
    return None


def update_deltalinks(deltalinks, deltalink_url, key, mytempdir):
    """Updates deltalink returned by AAD differential queries. 
    Updates deltalinks dict using 'key' as the key
    deltalinks -- total deltalinks set
    deltalink_url - specific deltalink url returned for the specific query
    key - key from COUNTERS dictionary
    return NAGIOS error code and error
    """
    global logger
    try:
        mytempdir = get_plugin_tempdir(mytempdir)
        if not mytempdir:
            return 3, 'Error. No temp dir path found for saving deltalinks file'
        deltalinks[key] = deltalink_url
        deltalinks_txt = json.dumps(deltalinks)
        fd, temp_path = tempfile.mkstemp()                
        with open(temp_path,'w') as temp_deltalinks_file: 
            temp_deltalinks_file.write(deltalinks_txt)
            temp_deltalinks_file.close()
            os.close(fd)
            shutil.copy (temp_path, 
                        mytempdir+'/azure_ad.dat')
            os.remove(temp_path)                
            return 0, 'All OK'            
    except (IOError, os.error) as e:
        logger.debug('error saving deltalinks')
        return 3, 'Internal error in saving deltalinks file'
    except:
        return 3, 'Other error'


def connect_to_aad(client_id, client_secret):
    """connects to AAD
    tenant_domain - AAD domain
    client_id - client Id
    client_secret - client secret
    return NAGIOS error code and connection data / error
    """
    global tenant_domain
    url = 'https://login.windows.net/'+tenant_domain+\
                '/oauth2/token?api-version=1.0'
    values = {'grant_type':'client_credentials',
              'client_id' : client_id,
              'client_secret' : client_secret,
              'resource' : '00000002-0000-0000-c000-000000000000/'\
                            'graph.windows.net@'+tenant_domain}
    data = urllib.urlencode(values)
    req = urllib2.Request(url, data)
    try:
        rsp = urllib2.urlopen(req)
        content = rsp.read()
        return 0, content
    except urllib2.HTTPError as e:
        return e.code, e.reason
    except urllib2.URLError as e:
        return e.reason[0], e.reason[1]


def extract_connection_token(content):
    """extracts connection token from AAD connection  """
    global logger
    global token
    global token_type
    logger.debug('Connected to Active Directory.')
    content_dict = ast.literal_eval(content)
    token = content_dict['access_token']
    token_type = content_dict['token_type']


def main():
    """Main procedure for Azure AD monitor utility."""
    global logger
    global tenant_domain
    args = handle_args()

    setup_logger(args.verbose)
    logger.debug('Connect to Active Directory.')
    tenant_domain = args.domain
    error_code, content = connect_to_aad(args.clientid, args.secret)    
    if error_code == 0:
        if args.key != 'status':
            extract_connection_token(content)
            error_code, error = check_aad_errors(args)
        else:
            error = 'Online'
    else:        
        error = 'Offline or Error (%s) connecting to Azure AD' % error_code
        error_code = 2

    if error_code == 0 and not error:
        error = "All OK"

    print error
    sys.exit(error_code)


if __name__ == '__main__':
    main()
