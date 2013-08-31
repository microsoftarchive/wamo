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
import exceptions
import logging
import os
import pyodbc
import sys
from datetime import datetime
from datetime import timedelta

logger = None

DBSIZE_DMV =  '''SELECT SUM(reserved_page_count)*8.0/1024 FROM 
                sys.dm_db_partition_stats;'''
OBJSIZE_DMV =  '''SELECT sys.objects.name, SUM(reserved_page_count)
                 * 8.0 / 1024 FROM sys.dm_db_partition_stats, sys.objects  
                WHERE sys.dm_db_partition_stats.object_id = 
                sys.objects.object_id GROUP BY sys.objects.name; '''
DBCONNECTIONS_DMV = '''SELECT e.connection_id, s.session_id, s.login_name, 
                s.last_request_end_time, s.cpu_time  FROM 
                sys.dm_exec_sessions s INNER JOIN sys.dm_exec_connections e
                ON s.session_id = e.session_id;'''
TOP5QUERIES_DMV = '''SELECT TOP 5 query_stats.query_hash AS "Query Hash", 
                  SUM(query_stats.total_worker_time) / 
                     SUM(query_stats.execution_count) AS "Avg CPU Time",
                  MIN(query_stats.statement_text) AS "Statement Text"
                  FROM 
                  (SELECT QS.*, 
                  SUBSTRING(ST.text, (QS.statement_start_offset/2) + 1,
                  ((CASE statement_end_offset 
                  WHEN -1 THEN DATALENGTH(st.text)
                  ELSE QS.statement_end_offset END 
                  - QS.statement_start_offset)/2) + 1) AS statement_text
                  FROM sys.dm_exec_query_stats AS QS
                  CROSS APPLY sys.dm_exec_sql_text(QS.sql_handle) as ST) 
                    as query_stats
                  GROUP BY query_stats.query_hash
                  ORDER BY 2 DESC;'''
QUERYPLAN_DMV = '''SELECT
                    highest_cpu_queries.plan_handle,  
                    highest_cpu_queries.total_worker_time, 
                    q.dbid, 
                    q.objectid, 
                    q.number, 
                    q.encrypted, 
                    q.[text] 
                    FROM 
                    (SELECT TOP 50  
                    qs.plan_handle,  
                    qs.total_worker_time 
                    FROM 
                        sys.dm_exec_query_stats qs 
                        ORDER BY qs.total_worker_time desc) AS 
                            highest_cpu_queries 
                        CROSS APPLY sys.dm_exec_sql_text(plan_handle) AS q 
                        ORDER BY highest_cpu_queries.total_worker_time desc'''
BWUSAGE_VIEW = 'select * from sys.bandwidth_usage where time > %s'
DBUSAGE_VIEW = 'select * from sys.database_usage where time > %s'
RESSTAT_VIEW = 'select * from sys.resource_stats where start_time > %s'
RESUSAGE_VIEW = 'select * from sys.resource_usage where time > %s'
OPSTATUS_VIEW = '''select resource_type_desc, operation, error_code, 
                error_desc, error_severity  from sys.dm_operation_status'''
DBCONNECTION_VIEW = '''select * from sys.database_connection_stats 
                where start_time > %s'''
EVENTLOG_VIEW = 'select * from sys.event_log where start_time > %s'

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
    """check result with respect to warning and critical range 
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
            nagios_message = '%s:%s %s' % ( prefix, nagios_message, unit or '')
        else:
            nagios_message = ''
    else:
        nagios_message = nagios_message % (strresult)
        nagios_message = '%s%s%s,warning=%s,critical=%s,' % \
            ( prefix, nagios_message, unit or '', warning or '', critical or '')
    return code, nagios_message


def analyze_dbsize(dbname, counter, row, warning, critical, verbosity):
    """analyze database size by comparing it with warning and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    nagios_message = 'Size:%s' 
    result = row[0]
    error_code, message = nagios_eval(result, warning, critical, nagios_message, \
                                      'MB', verbosity)
    return error_code, message


def analyze_objsize(dbname, counter, row, warning, critical, verbosity):
    """analyze object sizes by comparing them with warning and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    nagios_message = 'Object:%s,  Size:%%s' % (row[0],)
    result = row[1]
    error_code, message = nagios_eval(result, warning, critical, nagios_message, 
                                      'MB', verbosity)
    return error_code, message


def analyze_conn_info(dbname, counter, row, warning, critical, verbosity):
    """analyze connnection response time using warning and critical args
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    nagios_message = 'Database:%s, Login name:%s,  CPU time:%%s' % \
                            (dbname, row[2],)
    result = row[4]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, 'ms', verbosity)
    return error_code, message


def analyze_top5_queries(dbname, counter, row, warning, critical, verbosity):
    """Check top 5 database queries with warning and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    nagios_message = 'Database:%s, query:%s,  CPU time:%%s' % (dbname, row[2],)
    result = row[1]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, 'ms', verbosity)
    return error_code, message


def byte_to_hex( bytestr ):
    """ Convert a byte string to it's hex  representation. """
    return ''.join( [ '%02X ' % ord( x ) for x in bytestr ] ).strip()


def analyze_queryplan(dbname, counter, row, warning, critical, verbosity):
    """check query plan by comparing total woker time wrt warning and critical
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    #handle = byte_to_hex(str(row[0]))    
    strquery = str(row[6])
    nagios_message = 'Database:%s,  query:%s,  Total worker time:%%s' % \
                        (dbname, strquery, )
    result = row[1]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, 'ms', verbosity)
    return error_code, message

    
def analyze_bwusage(dbname, counter, row, warning, critical, verbosity):
    """Analyze bandwidth usage with warning and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    nagios_message = 'Database:%s, Time:%s, direction:%s, class:%s, '\
                    'time-period:%s, Size : %%s' % \
                    (row[1], str(row[0]), row[2], row[3], row[4],)
    result = row[5]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, 'MB', verbosity)
    return error_code, message


def analyze_dbusage(dbname, counter, row, warning, critical, verbosity):
    """check query plan CPU usage with warning and critical ranges. 
    Does not use db size 
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    nagios_message = 'Database:%s, Time:%s, Size %s, Quantity : %%s' % \
                        (dbname, str(row[0]), row[1], )
    result = row[2]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, 'MB', verbosity)
    return error_code, message


def analyze_resstat(dbname, counter, row, warning, critical, verbosity):
    """Check resource status by comparing total woker time with warning 
        and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    start_time = str(row[0])
    end_time = str(row[1])
    usage = str(row[4])
    size = str(row[5])

    nagios_message = 'Database:%s, Sku:%s - start_time:%s, end_time:%s,  '\
                        'Size:%s, Usage:%%s,' % (row[2], row[3], start_time, 
                                                 end_time, size,  )
    result = row[5]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, 'MB', verbosity)
    return error_code, message


def analyze_resusage(dbname, counter, row, warning, critical, verbosity):
    """Check resource usage with warning and critical ranges. 
        Does not use size
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    query_time = str(row[0])
    size = str(row[4])
    nagios_message = 'Database:%s, Sku:%s - time:%s, Size:%s, Usage:%%s' \
                % ( row[1], row[2], query_time, size,)
    result = row[3]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, '%', verbosity)
    return error_code, message


def analyze_opstatus(dbname, counter, row, warning, critical, verbosity):
    """Analyze operation error_code - success, warning, or error - 
    comparing total woker time with warning and critical ranges
    opstatus values are: 0 - success, 1 - warning and 2 - error
    use warning <1 (e.g. 0.9) and critical < 2 (e.g. 1.9) to get Nagios status
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """

    nagios_message = 'Resource desc:%s, Operation:%s,  error_desc:%s, '\
                        'Severity:%s, error_code:%%s' % \
                        ( row[0], row[1], row[3], row[4], )
    result = row[2]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, '', verbosity)
    return error_code, message


def analyze_conection(dbname, counter, row, warning, critical, verbosity):
    """Analyze connection failures by comparing total woker 
    time with warning and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    start_time = str(row[1])
    end_time = str(row[2])
    success = str(row[3])
    conn_failure = str(row[5])
    term_conn = str(row[6])
    throttled_conn = str(row[7])
    nagios_message = 'Database:%s, - start_time:%s, end_time:%s, '\
                    'Success Count:%s, Conn Failure Count:%s, '\
                    'Terminated Conn: %s, Throttled conn:%s, '\
                    'Total Failure Count:%%s,  ' % (row[0],  start_time, 
                                                    end_time,  success,  
                                                    conn_failure, term_conn, 
                                                    throttled_conn,)         
    result = row[4]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, '', verbosity)
    return error_code, message


def analyze_eventlog(dbname, counter, row, warning, critical, verbosity):
    """Analyze SQL event log  by comparing severity of the log message 
    with warning and critical ranges
    dbname - name of database
    counter - entry in the COUNTERS list
    row - perf data from SQL server as an output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """

    database = row[0]
    start_time = str(row[1])
    count = str(row[8])

    nagios_message = 'Database:%s, - start_time:%s, Sub-type descr:%s, '\
                    'Event count: %s, description:%s, Severity:%%s' % \
                    (database,  start_time,  row[6],  count, row[9],  )   
    result = row[7]
    error_code, message = nagios_eval(result, warning, critical, 
                                      nagios_message, '', verbosity)
    return error_code, message    


SQL_QUERIES     = {
    'dbsize'        : { 'help' : 'Database size',
                      'query'     : DBSIZE_DMV,
                      'size'      : 'single',
                      'printfn'   : analyze_dbsize,
                      },           
    'objsize'       : { 'help'      : 'Database Object Size ',
                      'query'     : OBJSIZE_DMV,
                      'size'      : 'multiple',
                      'printfn'   : analyze_objsize,
                      },                   
    'connections'   : { 'help'      : 'Database Connections',
                      'query'     : DBCONNECTIONS_DMV,
                      'size'      : 'multiple',
                      'printfn'   : analyze_conn_info,

                      },                   
    'top5queries'   : { 'help'      : 'Top5 Queries',
                      'query'     : TOP5QUERIES_DMV,
                      'size'      : 'multiple',
                      'printfn'   : analyze_top5_queries,

                      },                   
    'queryplan'     : { 'help'      : 'Monitor Query Plan',
                      'query'     : QUERYPLAN_DMV,
                      'size'      : 'multiple',
                      'printfn'   : analyze_queryplan,
                      },                   
    'bwusage'       : { 'help'      : 'Bandwidth Usage (Cumulative)',
                      'query'     : BWUSAGE_VIEW,
                      'frequency' : 'hourly',
                      'size'      : 'multiple',
                      'printfn'   :  analyze_bwusage,
                      'db'        : 'master',
                      },                   
    'dbusage'       : { 'help'      : 'Databse usage (Daily)',
                      'query'     : DBUSAGE_VIEW,
                      'size'      : 'multiple',
                      'printfn'   :  analyze_dbusage,
                      'db'        : 'master',
                      'frequency' : 'daily'
                      },                   
    'resstat'       : { 'help'      : 'Databse Resource Status (Daily)',
                      'query'     : RESSTAT_VIEW,
                      'size'      : 'multiple',
                      'printfn'   :  analyze_resstat,
                      'db'        : 'master',
                      'frequency' : 'hourly'
                      },                   
    'resusage'       : { 'help'      : 'Databse Resource usage (Daily)',
                      'query'     : RESUSAGE_VIEW,
                      'size'      : 'multiple',
                      'printfn'   :  analyze_resusage,
                      'db'        : 'master',
                      'frequency' : 'daily'
                      },                   
    'opstatus'       : { 'help'      : 'Databse Op Status (Daily)',
                      'query'     : OPSTATUS_VIEW,
                      'size'      : 'multiple',
                      'printfn'   :  analyze_opstatus,
                      'db'        : 'master',
                      },                   
    'dbconnection'   : { 'help'      : 'Databse connection stat (Daily)',
                      'query'     : DBCONNECTION_VIEW,
                      'size'      : 'multiple',
                      'printfn'   :  analyze_conection,
                      'db'        : 'master',
                      'frequency' : '5min'
                      },                   
    'eventlog'       : { 'help'      : 'Event_log',
                      'query'     : EVENTLOG_VIEW,
                      'size'      : 'multiple',
                      'printfn'   :  analyze_eventlog,
                      'db'        : 'master',
                      'frequency' : 'hourly'
                      },                      
}


def handle_args():
    """Create the parser, parse the args, and return them."""
    parser = argparse.ArgumentParser(description='Check SQL Azure',
                                     epilog='(c) MS Open Tech')
    parser.add_argument('hostname', help='Azure SQL Server Address to check')    

    parser.add_argument(
        '-u', '--username',
        required=True,
        help='Specify MSSQL User Name',
        dest='user')
    parser.add_argument(
        '-p', '--password',
        required=False,
        help='Specify MSSQL Password',
        dest='password')

    parser.add_argument(
        '-d', '--database',
        required=True,
        help='Specify Azure DB',
        dest='database')
    
    parser.add_argument('-w', '--warning', required=False, dest='warning',
                        help='Specify warning range')
    parser.add_argument('-c', '--critical', required=False, dest='critical',
                        help='Specify critical range')
    parser.add_argument('-k', '--key', required=True, dest='key',
                        help='Specify key for the DMV or SQL view')
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


def connect_db(options, db):
    """Connects to SQL azure database, using command line options."""
    host = options.hostname
    start = datetime.now()
    if os.name != 'nt':
        mssql = pyodbc.connect(
                driver='FreeTDS',
                TDS_Version = '8.0', # Use for
                server = host,
                port = 1433,
                database = db,
                uid = options.user,
                pwd = options.password)
    else:
        try:
            connstr = 'Driver={SQL Server Native Client 10.0};Server=tcp:'+\
                        host+',1433;Database='+db+';Uid='+options.user+';Pwd='+\
                        options.password+';Encrypt=yes;Connection Timeout=30;'
            mssql = pyodbc.connect(connstr)
        except:
            return None, 0

    total = datetime.now() - start
    return mssql, total


def execute_query(mssql, dbname, sq_query,  warning = None, critical = None, 
                  verbosity = 0):    
    """execute SQL query and   by comparing severity of the log message with 
    warning and critical ranges
    mssql - mssql object
    dbname - name of database
    sq_query - entry in the COUNTERS list output of the SQL query/DMV
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    total_error_code = 0
    errors = []
    query = sq_query['query']
    if 'frequency' in sq_query:
        if sq_query['frequency'] == 'hourly':
            latest_utctime = datetime.utcnow()
            hourly_query_clause = (latest_utctime - 
                                   timedelta(hours = 1, minutes = 30)).\
                                    strftime('\'%Y%m%d %H:00:00\'')
            query = query % hourly_query_clause
        elif sq_query['frequency'] == 'daily':
            latest_utctime = datetime.utcnow()
            daily_query_clause = (latest_utctime - 
                                  timedelta(days = 1, hours = 12)).\
            strftime('\'%Y%m%d %H:00:00\'')
            query = query % daily_query_clause
        elif sq_query['frequency'] == '5min':
            latest_utctime = datetime.utcnow()
            daily_query_clause = (latest_utctime - 
                                  timedelta(minutes = 8)).\
            strftime('\'%Y%m%d %H:%M:00\'')
            query = query % daily_query_clause

    cur = mssql.cursor()                        
    cur.execute(query)
    if sq_query['size'] == 'single':
        row = cur.fetchone()
        total_error_code, error = sq_query['printfn'] \
                          (dbname, sq_query, row, warning, critical, verbosity)
        errors.append(error)
    else:
        rows = cur.fetchall()
        for row in rows:
            error_code, error = sq_query['printfn']\
                    (dbname, sq_query, row, warning, critical, verbosity)
            total_error_code = max(total_error_code, error_code)
            if error != '':
                errors.append(error)
    return total_error_code, ', '.join(errors)


def check_sqlazure_errors(mssql_db, mssql_master, dbname, sq_key, 
                          warning = None, critical = None, verbosity = 0):
    """execute SQL query and   by comparing severity of the log message 
    with warning and critical ranges
    mssql_db - mssql object for the the azure  db
    mssql_master - mssql object for the the mssql master db
    dbname - name of database
    host - Azure AD 
    sql_key -- SQL key as input to the command
    warning - warning range argument to the command
    critical - critical range argument to the command
    verbosity - verbose argument to the command. 
    """
    total_error_code = 0
    errors = []
    if sq_key not in SQL_QUERIES:
        return 3, 'Key not found:{0}'.format(sq_key)
    sql_query = SQL_QUERIES[sq_key]
    try:
        if 'db' in sql_query and sql_query['db'] == 'master':
            error_code, error = execute_query(mssql_master, 'master', 
                                              sql_query, warning, critical, 
                                              verbosity)
        else:
            if mssql_db != None:
                error_code, error = execute_query(mssql_db, dbname, 
                                                  sql_query, warning, critical, 
                                                  verbosity)
        total_error_code = max (total_error_code, error_code)
        errors.append(error)
    except Exception, e:
        total_error_code = 3
        errors.append('%s failed with: %s' % (sq_key, e))
    return  total_error_code, ', '.join(errors)


def main():
    """Main procedure for Azure SQL monitor utility."""

    args = handle_args()
    
    global logger
    setup_logger(args.verbose)    
    logger.debug('Connecting to d/b.')        
    mssql_db = None
    mssql_master = None
    try:
        if args.database:
            mssql_db, _ = connect_db(args, args.database)
        mssql_master, _ = connect_db(args, 'master')
    except exceptions.Exception, e:
        print e
        print 'Error connecting to database'
        sys.exit(3)
    if not mssql_db or not mssql_master:
        print 'Error connecting to database'
        sys.exit(3)

    error = ''
    error_code = 0
    error_code, error =  check_sqlazure_errors(mssql_db, 
                                               mssql_master, 
                                               args.database, 
                                               args.key, 
                                               args.warning, 
                                               args.critical, 
                                               args.verbose )

    if error_code == 0:
        if args.verbose <= 1:
            error = 'OK'
		
    print error
    sys.exit(error_code)


if __name__ == '__main__':
    main()
