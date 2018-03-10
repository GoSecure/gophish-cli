#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Config file of the Gophish command line interface.

@author: Martin Dubé
@organization: Gosecure inc.
@license: MIT License
@contact: mdube@gosecure.ca

Copyright (c) 2017, Gosecure
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
import datetime

#
# Step 1: Gophish configuration
#
# Just the basic configuration for basic features
#
API_KEY = ''
API_URL = 'http://127.0.0.1:3333'

#
# Step 2: Campaign configuration
#
# Information regarding your campaign. Most comes from the gophish WebUI.
CAMPAIGN_NAME = 'John Doe'
CAMPAIGN_URL = 'https://path.toyourwebsite.com'

WORKING_DIR = '/path/to/working/dir'
EMAILS_PATH = WORKING_DIR + 'emails.txt'

# Landing Pages
LP_NAME = 'Landing Page Name'

# Two specific fields required by --print-creds to properly parse the JSON payloads.
# Update the fields based on your landing pages user and password fields.
LP_USER_FIELD = 'cUser'
LP_PWD_FIELD = 'cPass'

# Email Template
ET_NAME = 'Email Template Name'

# Sending Profiles
SP_NAME = 'Sending Profile Name'

# Batch Management Settings
GROUP_SIZE = 50
START_INTERVAL = 1    # Unit = minutes. Default=1. Increase when you have more than 10 batch.
BATCH_INTERVAL = 1    # Unit = minutes

# Verify TLS when testing credentials
# Default is True
VERIFY_TLS = True

# Owa login testing settings 
OWA_DOMAIN = 'DOMAIN'
OWA_SERVER = 'outlook.example.com'

# Netscaler login testing settings
NETSCALER_SERVER = 'vpn.example.com'

# Juniper (Secure Access SSL VPN)
JUNIPER_DOMAIN = 'DOMAIN'
JUNIPER_SERVER = 'vpn.example.com'
# HINT: Consider verifying the URI as some organizations have multiple
#       URIs which are 2FA or 1FA. The default one is often 2FA. 
#       For istance, /url/ can become /url_XX/, where XX is a number.
JUNIPER_URI = '/dana-na/auth/url/login.cgi'
# HINT: Find it in the source code of the login page. Look for a hidden 
#       input field named "realm".
JUNIPER_REALM = 'bla'
#
# Step 3: Things that should not change for most users
#
FILE_DATE_FMT = '%Y%m%d_%H%M%S'
FILE_DATE = datetime.datetime.now().strftime(FILE_DATE_FMT)

CAMPAIGN_NAME_TPL = '%s - Group %i'
CAMPAIGN_PREFIX = CAMPAIGN_NAME_TPL[:-2] % CAMPAIGN_NAME
RESULTS_PATH = WORKING_DIR + 'campaign_results_%s.csv' % CAMPAIGN_NAME
CREDS_PATH = WORKING_DIR + 'campaign_creds_%s_%s.csv' % (FILE_DATE, CAMPAIGN_NAME)
JSON_PATH = WORKING_DIR + 'campaign_raw_%s.json' % CAMPAIGN_NAME
GEOIP_PATH = WORKING_DIR + 'campaign_geoip_%s.csv' % CAMPAIGN_NAME

# Reporting

EXCLUDED_IP = []

GOPHISH_HOST = ''
GOPHISH_SSH_PORT = 22
GOPHISH_SSH_USER = 'root'
GOPHISH_SSH_PASS = None
GOPHISH_SSH_KEY = '/path/to/key'
GOPHISH_SSH_KEY_PASSPHRASE = 'some_pass'

# Gophish timestamps are in UTC. This will put dates as this timezone.
GOPHISH_TIMEZONE = "America/Toronto"

APACHE_HOST = GOPHISH_HOST
APACHE_SSH_PORT = GOPHISH_SSH_PORT
APACHE_SSH_USER = GOPHISH_SSH_USER
APACHE_SSH_PASS = GOPHISH_SSH_PASS
APACHE_SSH_KEY = GOPHISH_SSH_KEY
APACHE_SSH_KEY_PASSPHRASE = GOPHISH_SSH_KEY_PASSPHRASE
APACHE_LOGS_FOLDER = '/var/log/apache2/'
APACHE_LOGS_PREFIX = 'path.toyourwebsite.com'
# Take if from /etc/apache2/apache2.conf. The line starts with LogFormat. Currently using the "combined" one.
APACHE_LOGS_FORMAT = "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\""
APACHE_MALWARE_NAME = 'malware.zip'

EMPIRE_API_URL = 'https://127.0.0.1:1337'
EMPIRE_API_KEY = 'some_key'

SENDGRID_API_KEY = 'some_key'

#
# By default, we disable SSL verification as gophish uses a self-signed cert.
#
import gophish.client
import requests
from requests.packages import urllib3

class GophishClient(gophish.client.GophishClient):
    """ A standard HTTP REST client used by Gophish """

    def __init__(self, api_key, host, **kwargs):
        super(GophishClient, self).__init__(api_key, host, **kwargs)

    def execute(self, method, path, **kwargs):
        """ Executes a request to a given endpoint, returning the result """

        url = "{}{}".format(self.host, path)
        kwargs.update(self._client_kwargs)
        response = requests.request(
            method, url, params={"api_key": self.api_key}, verify=False, **kwargs)
        return response

# Just to remove a SubjectAltNameWarning.
urllib3.disable_warnings()

#
# Step 4: Advanced TLS settings
#
#
# 
# Uncomment to configure TLS Client certificates or other TLS settings.
#
#
#import ssl
#import gophish.client
#from requests import Session
#from requests.adapters import HTTPAdapter
#from requests.packages.urllib3.poolmanager import PoolManager
#from requests.packages import urllib3
#
#class TLSHttpAdapter(HTTPAdapter):
#    '''An HTTPS Transport Adapter that uses an arbitrary SSL version.'''
#
#    def init_poolmanager(self, connections, maxsize, block=False):
#        self.poolmanager = PoolManager(num_pools=connections,
#                                       maxsize=maxsize,
#                                       block=block,
#                                       ssl_version=ssl.PROTOCOL_TLSv1_2,
#                                       cert_reqs='CERT_REQUIRED')
#
#class GophishClient(gophish.client.GophishClient):
#    """ A standard HTTP REST client used by Gophish """
#    def __init__(self, api_key, host, cert_file=None, ca_file=None, **kwargs):
#        super(GophishClient, self).__init__(api_key, host, **kwargs)
#        self.session = Session()
#        self.session.mount(API_URL, TLSHttpAdapter())
#        self.cert_file = '/path/to/client_cert.pem'
#        self.ca_file = '/path/to/root_ca.crt'
#    
#    def execute(self, method, path, **kwargs):
#        """ Executes a request to a given endpoint, returning the result """
#
#        url = "{}{}".format(self.host, path)
#        kwargs.update(self._client_kwargs)
#        response = self.session.request(method, url, params={"api_key": self.api_key}, 
#                                        cert=(self.cert_file), verify=self.ca_file, **kwargs)
#        return response
#
