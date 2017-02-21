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

# Owa login testing settings
OWA_DOMAIN = 'DOMAIN'
OWA_SERVER = 'outlook.example.com'

#
# Step 3: Things that should not change for most users
#
CAMPAIGN_NAME_TPL = '%s - Group %i'
CAMPAIGN_PREFIX = CAMPAIGN_NAME_TPL[:-2] % CAMPAIGN_NAME
RESULTS_PATH = WORKING_DIR + 'campaign_results_%s.csv' % CAMPAIGN_NAME
CREDS_PATH = WORKING_DIR + 'campaign_creds_%s.csv' % CAMPAIGN_NAME

#
# Step 4: Advanced TLS settings
#
# 
# If you have configured Gophish behind a reverse proxy with TLS, uncomment 
# and configure the classes below. 
#
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
#class GophishClient2(gophish.client.GophishClient):
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
