#!/usr/bin/env python3
from __future__ import absolute_import
from __future__ import print_function
import six.moves.configparser
import argparse
import json
import logging
import os
import sys
import calendar
import requests
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta
from collections import deque

class BaseLog(object):

    def __init__(self, config, log_path):
        self.config    = config
        self.events    = deque()
        self.url       = False
        self.max_epoch = 0
        self.verbose   = config['verbose']
        self.corp_name = config['corp_name']
        self.site      = config['site']
        self.api_host  = config['api_host']
        self.log_count = 0

        if 'email' in config:
            self.email          = config['email']
        if 'api_token' in config:
            self.api_token      = config['api_token']
        if 'session_token' in config:
            self.session_token  = config['session_token']

        # We need to give SigSci 5 minutes to ingest, aggregate, and process
        # https://docs.signalsciences.net/developer/extract-your-data/#example-usage
        until_time = datetime.utcnow().replace(second=0, microsecond=0)
        until_time = until_time - timedelta(minutes=5)
        self.until_time = calendar.timegm(until_time.utctimetuple())

        # Set up our logger
        log_file   = os.path.join(log_path, self.__class__.__name__) + '-' + config['site'] + '.log'
        logger     = logging.getLogger(self.__class__.__name__ + '-' + config['site'])
        formatter  = logging.Formatter('%(message)s')
        loghandler = TimedRotatingFileHandler(log_file,
                                              encoding='utf-8',
                                              when='midnight',
                                              interval=1,
                                              backupCount=7)
        loghandler.setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
        loghandler.setFormatter(formatter)
        logger.addHandler(loghandler)

        self.logger = logger

    def get_events(self):
        #If we have a self generated token we can use it in the headers
        if self.api_token:
            self.headers = {
                'Content-type': 'application/json',
                'x-api-user': self.email,
                'x-api-token': self.api_token
            }
        # If we've authenticated using a username & password, we get a session token.  That token needs to be sent in the request headers.
        else:
            self.headers   = {
                'Content-type': 'application/json',
                'Authorization': 'Bearer %s' % self.session_token
            }

        try:
            # TODO: for memory reasons, we should write out each page to the log, and reset the events array with each page
            # SigSci paginates by 1,000 requests.  If there's a next uri parameter, keep fetching that until we're done
            self.fetch_done = False
            while not self.fetch_done:
                if self.verbose: print("Fetching next 1,000 logs")
                self.fetch_events()
                if self.verbose: print("Writing last 1,000 logs")
                self.write_logs()

        except RuntimeError as e:
            errmsg = e.args[0]
            if errmsg == 'Received 429 Too Many Requests':
                print("SigSci is throttling requests, exiting.")
                sys.exit(0)

    def fetch_events(self):
        raise NotImplementedError

    def write_logs(self):
        raise NotImplementedError

    def set_from_time(self,new_from_time):
        self.from_time = new_from_time

class RequestLog(BaseLog):
    def __init__(self, config, site):
        BaseLog.__init__(self, config, site)

    def fetch_events(self):
        # Note that the API limits the until time to a max of 5 minutes ago
        # https://docs.signalsciences.net/developer/extract-your-data/#example-usage
        if not self.url:
            self.url = self.api_host + ('/api/v0/corps/%s/sites/%s/feed/requests?from=%s&until=%s' % (self.corp_name, self.site, self.from_time, self.until_time))

        if self.from_time == self.until_time:
            print ('Do not run this script multiple times per minute.')
            self.fetch_done = True
            return False

        response_raw = requests.get(self.url, headers=self.headers)
        if response_raw.status_code != 200:
            print ('Unexpected status: %s response %s' % (response_raw.status_code, response_raw.text))
            self.fetch_done = True
            return False
        response = json.loads(response_raw.text)
        # Add the requests to our events array
        self.events.extend(response['data'])

        if response['next']['uri'] == '':
            self.fetch_done = True
        else:
            self.url = self.api_host + response['next']['uri']

    def write_logs(self):
        fmtstr = (
            '%(epochtimestamp)s,'
            'serverHostname="%(serverHostname)s",'
            'remoteIP="%(remoteIP)s",'
            'remoteHostname="%(remoteHostname)s",'
            'remoteCountryCode="%(remoteCountryCode)s",'
            'method="%(method)s",'
            'serverName="%(serverName)s",'
            'protocol="%(protocol)s",'
            'path="%(path)s",'
            'uri="%(uri)s",'
            'responseCode="%(responseCode)s",'
            'responseSize="%(responseSize)s",'
            'responseMillis="%(responseMillis)s",'
            'agentResponseCode="%(agentResponseCode)s",'
            'tags="%(tags)s",'
            'userAgent="%(userAgent)s"'
        )
        event = None
        while True:
            try:
                event = self.events.popleft()
            except IndexError:
                break

            # Grab our tag names and add them to an array
            tags = []
            for tag in event['tags']:
                tags.append(tag['type'])

            event['tags'] = ','.join(tags)
            utc_time = datetime.strptime(event['timestamp'],"%Y-%m-%dT%H:%M:%SZ")
            event['epochtimestamp'] = calendar.timegm(utc_time.utctimetuple())
            if event['epochtimestamp'] > self.max_epoch:
                self.max_epoch = event['epochtimestamp']
            # Write our event to the log
            self.logger.info(fmtstr % event)
            self.log_count += 1

def load_config(config_path):
    """
    Return a config created using the parameters
    stored in a config file.
    """
    config = six.moves.configparser.ConfigParser()
    config.read(config_path)
    config_s = dict(config.items('sigsci'))

    # Change csv to array
    config_s['site_names'] = [x.strip() for x in config_s['site_names'].split(',')]

    return config_s

def parse_args():
    parser = argparse.ArgumentParser(description='Download Signal Sciences logs to the local filesystem for LogRhythm consumption.')

    parser.add_argument("-c", "--config-file", help="Path to sigsci.conf, defaults to sigsci.conf in same directory as this script.",
                        default=os.path.join(sys.path[0], 'sigsci.conf'))
    parser.add_argument("-l", "--log-path", help="Path to store the log file in, defaults to the 'logs' directory beneath this script.",
                        default=os.path.join(sys.path[0], 'logs'))
    parser.add_argument("-s", "--state-path", help="Path to store the state file in, defaults to the same directory as the log file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode.")
    return parser.parse_args()

def load_state_from_file(statefile):
    try:
        with open(statefile, 'r') as json_file:
            state = json.load(json_file)
    except:
        state = {}
    return state

def write_state_to_file(statefile,state):
    try:
        with open(statefile, 'w') as outfile:
            json.dump(state, outfile)
    except IOError:
        print("Unable to write to " + statefile + ", exiting.")
        sys.exit(1)

def fetch_session_token(config):
    auth = requests.post(
        config['api_host'] + '/api/v0/auth',
        data = {"email": config['email'], "password": config['password']}
    )

    if auth.status_code == 401:
        print ('Invalid login. ' + auth.text)
        sys.exit(1)
    elif auth.status_code != 200:
        print ('Unexpected status: %s response %s' % (auth.status_code, auth.text))
        sys.exit(1)

    return auth.json()['token']

def twenty_four():
    from_time = (datetime.utcnow().replace(second=0, microsecond=0)) - timedelta(hours=24)
    from_time = calendar.timegm(from_time.utctimetuple())
    return from_time


def main():
    # Parse the commandline args, load our config, and set our paths
    args        = parse_args()
    config_path = args.config_file
    log_path    = args.log_path
    state_path  = args.state_path if args.state_path else args.log_path
    state_file  = os.path.join(state_path,'.state.json')
    if not os.path.exists(log_path):
        os.makedirs(log_path)

    # Load our last timestamps to prevent dupes
    state = load_state_from_file(state_file)

    # This is our config
    config = load_config(config_path)
    if args.verbose:
        config['verbose'] = True
    else:
        config['verbose'] = False

    # Get our auth token if necessary
    if 'api_token' not in config:
        session_token = fetch_session_token(config)
        config['session_token'] = session_token

    for logclass in (RequestLog,): # Support for future other logtypes
        for site in config['site_names']:
            print ('Fetching requests since last run for site \'' + site +'\'')

            config['site'] = site
            log = logclass(config,log_path)

            # Load our previous state, creating the default if it doesn't exist
            state_index = log.__class__.__name__ + "-" + site
            try:
                from_time = state[state_index]['last_timestamp']

                # The SigSci API requires 'from' and until epochs to be even minutes.
                # We bump up the from time to the next minute.
                if from_time % 60 != 0:
                    from_time += (60 - (from_time % 60))
            except KeyError:
                # Only grab the last 24 hours if we haven't ran before, this is limited by the API
                from_time = twenty_four()
                state[state_index] = {'last_timestamp': 0}

            if from_time < twenty_four():
                from_time = twenty_four()

            log.set_from_time(from_time)
            # Fetch the events
            log.get_events()
            if args.verbose: print("Wrote " + str(log.log_count) + " logs from site " + site + " of type " + log.__class__.__name__)
            # Update our last recorded timestamp
            if args.verbose: print("Last timestamp in epoch: %s" % log.max_epoch)
            state[state_index]['last_timestamp'] = log.max_epoch

            # Save our state to a json file if we have a last log received
            if log.max_epoch != 0:
                write_state_to_file(state_file, state)

if __name__ == '__main__':
    main()
