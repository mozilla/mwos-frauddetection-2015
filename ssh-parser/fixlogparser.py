#!/usr/bin/env python

"""
Description:

    Analyzes a given log file and prints out the following:
    
        1) The number of successful and unsuccessful requests
        2) The top 5 messages that are reported in the logs
        3) Of those top 5 messages, which method did the error occur

    There is also an additional option to gather the data
    across a set of hosts and aggregate the data. As it is coded
    now, it is more of a Proof-of-Concept and executes only against
    a set of files locally on disk, but can be modified
    to do the right thing.
"""

import argparse
import json
import sys
import subprocess
import operator
import os.path


###################################
# Argument Parser and Other Setup #
###################################


parser = argparse.ArgumentParser(description='Log analyzer to scan and provide statistics around the errors that occurred in a log')
parser.add_argument('-s', metavar='SERVER', dest='server', type=argparse.FileType('r'), default=sys.stdin,
                    help='A file containing a list of servers to connect to')
parser.add_argument('-f', metavar='LOG_FILE', dest='log_file', type=argparse.FileType('r'), default=sys.stdin,
                    help='A local log file to analyze')
parser.add_argument('-j', '--json', action='store_true',
                    help="Enables printing out as json")
parser.add_argument('-v', '--verbose', action='store_true',
                    help="Turns on verbose output")
parser.add_argument('-d', '--debug', action='store_true',
                    help="Turns on debug output")
parser.add_argument('--remote', action='store_true',
                    help="Only when this is specified will it go out and walk through scan the logs across the specified list of host, aggregrate the results, and provide an aggregated report. Otherwise, A local log file must be specified")

args = parser.parse_args()
if len(sys.argv) == 1:
    parser.print_help()
    exit(1)
if args.verbose or args.debug: print args


########
# Main #
########


def main(argv):
    """
        main():
                The main logic of the program. All logic goes through here
    """

    if args.remote:
        ##################################################
        # Execute everything under here against a set of #
        # remote hosts and aggregate the analyzed data   #
        # across them                                    #
        ##################################################

        ## Double-check that the server file has been specified
        if args.server.name == '<stdin>':
            parser.print_help()
            print
            print '[ERROR] Server not specified'
            exit(1)

        ## Walk through all hosts in the server, and remotely request for the
        ## analysis results in json format
        remote_data = {}
        while args.server:
            line = args.server.readline()
            line = line.rstrip("\n")
            
            ## Exit if EOF
            if not line: break
            
            if args.verbose: print line
            
            ## Split line
            host = line.split()[0]
            ## TODO: Remove my hardcoded username
            remote_data[host] = remote_execute('psalas', host, args.verbose)

        ## Optionally print out the raw json analysis
        if args.json:
            print json.dumps(remote_data, indent=4)
            exit(0)

        total = 0
        total_success = 0
        total_failures = 0
        aggregate_histogram = {}

        for host in remote_data.keys():
            total += remote_data[host]['total']
            total_success += remote_data[host]['total_success']
            total_failures += remote_data[host]['total_failures']
            histogram_by_message = remote_data[host]['histogram_by_message']

            for message in histogram_by_message.keys():
                if message in aggregate_histogram: aggregate_histogram[message] += histogram_by_message[message]
                else: aggregate_histogram[message] = histogram_by_message[message]

        print 'Summary'
        print '======'
        print
        print "  Total Successes: %s" %(total_success)
        print "  Total Failures: %s" %(total_failures)
        print

        sorted_histogram_by_message = sorted(aggregate_histogram.iteritems(), key=operator.itemgetter(1), reverse=True)
        index = 1
        if args.verbose: print "All Errors"
        else: print "The TOP 5 Errors"
        print "=================="
        for data in sorted_histogram_by_message:
            if not args.verbose and index > 5: break
            percentage = 100 * float(data[1])/float(total_failures)
            message = data[0]
            error_total = data[1]
            print "%s. %s (%.2f%% - %s errors)" %(index, message, percentage, error_total)
            index += 1

    else:
        ####################################################
        # This is reserved for analysis of local log files #
        ####################################################
        
        ## Double-check that the log file has been specified
        if args.log_file.name == '<stdin>':
            parser.print_help()
            print
            print '[ERROR] Log file not specified'
            exit(1)

        log_data = read_file(args.log_file, args.verbose, args.debug)

        if args.debug: 
            print
            print log_data
            print

        histogram = log_data['histogram']
        histogram_by_message = log_data['histogram_by_message']
        total_success = log_data['total_success']
        total_failures = log_data['total_failures']

        if args.json: 
            print json.dumps(log_data, indent=4)
            exit(0)

        print 'Summary'
        print '======'
        print
        print "  Total Successes: %s" %(total_success)
        print "  Total Failures: %s" %(total_failures)
        print

        sorted_histogram_by_message = sorted(histogram_by_message.iteritems(), key=operator.itemgetter(1), reverse=True)
        index = 1
        if args.verbose: print "All Errors"
        else: print "The TOP 5 Errors"
        print "=================="
        for data in sorted_histogram_by_message:
            if not args.verbose and index > 5: break
            percentage = 100 * float(data[1])/float(total_failures)
            message = data[0]
            error_total = data[1]
            print "%s. %s (%.2f%% - %s errors)" %(index, message, percentage, error_total)
            index += 1

            for method in histogram[data[0]]:
                method_percentage = 100 * float(histogram[message][method])/float(error_total)
                print "  - %.2f%% %s" %(method_percentage, method)


####################
# Helper Functions #
####################


def read_file(log_file, verbose, debug):
    """read_file() processes the specified file and returns the analyzed results"""

    result = {
        'total': 0, 
        'total_success': 0, 
        'total_failures': 0,
        'histogram': {},
        'histogram_by_message': {}
        }
    histogram = {}
    line_num = 1

    ## Iterate through file
    if verbose: print "RAW File contents:"

    while log_file:
        line = log_file.readline()
        line = line.rstrip("\n")
        if not line: break

        if verbose: print "%d: %s" % (line_num, line)
        line_num += 1
        if "#" in line: continue

        ## Split the attributes on the line
        args = line.split('"')
        logattr = args[0].split()
        ip = logattr[0]
        date = logattr[1]
        code = logattr[2]
        method = logattr[3]
        message = args[1]
        result['total'] += 1
        if debug: print logattr, message

        ## Add anything and everything that did not result in 200 response code
        if code != '200': 
            result['total_failures'] += 1
            if debug: print "> Adding %s %s" % (code, message)
            if message in histogram:
                if method in histogram[message]: histogram[message][method] += 1
                else: histogram[message][method] = 1
            else: histogram[message] = {method: 1}
        else:
            result['total_success'] += 1

    ## Create a histogram based on the messages
    histogram_by_message = {}
    for message in histogram.keys():
        total = 0
        for method in histogram[message]:
            total += histogram[message][method]
        histogram_by_message[message] = total

    result['histogram'] = histogram
    result['histogram_by_message'] = histogram_by_message
    return result

def remote_execute(user, host, verbose):
    """remote_execute() Runs a remote-command to execute the log-parser.py on a remote host"""

    cmd = "ssh %s@%s ./log-parser.py -f server.log --json" %(user, host)
    
    print "------ %s@%s ------" %(user, host)
    if verbose: print "$ %s" %(cmd)
    
    ## TODO: Fix this part so that it is not against a local file
    local_command = "./log-analyzer.py -f ../logs/%s.log --json" %(host)
    p = subprocess.Popen(local_command,
                         shell=True,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         close_fds=True)
    stdout, stderr = p.communicate()
    return json.loads(stdout)

if __name__ == "__main__":
    main(sys.argv[1:])