#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Config file of the Gophish command line interface.

@author: Martin Dubé
@organization: Gosecure inc.
@license: Modified BSD License
@contact: mdube@gosecure.ca

Copyright (c) 2017, Gosecure
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
# If you have configured Gophish behind a reverse proxy with TLS, configure
# the classes below
#

# Only for TLS configuration
#
# Uncomment this block to overwrite TLS settings such as CA file path, protocol version, etc.
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
