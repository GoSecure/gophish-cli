#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Reporting class to gather information from the campaign

@author: Martin Dubé
@organization: Gosecure inc.
@license: MIT License
@contact: mdube@gosecure.ca

Copyright (c) 2018, Gosecure
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

import os
import ssl
import time
import json
import config
import paramiko
import urllib.request

class GophishReporter():
    timeline = None
    results = None
    empire_agents = None
    excluded_ip = []
    stats = {}

    out_folder = config.WORKING_DIR + 'report_%s/' % time.strftime("%Y%m%d-%H%M%S")
    apache_folder = out_folder + 'apache_logs/'

    def __init__(self, timeline, results):
        self.timeline = timeline
        self.results = results
        self.excluded_ip = config.EXCLUDED_IP

    def _setup_out_folder(self):
        if not os.path.exists(self.out_folder):
            print("Creating folder: %s" % self.out_folder)
            os.makedirs(self.out_folder)

        if not os.path.exists(self.apache_folder):
            print("Creating folder: %s" % self.apache_folder)
            os.makedirs(self.apache_folder)

    def _ssh_agent_auth(self, transport, username):
        """
        Attempt to authenticate to the given transport using any of the private
        keys available from an SSH agent
        """
    
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if len(agent_keys) == 0:
            return
    
        for key in agent_keys:
            print('Trying ssh-agent key %s' % key.get_fingerprint())
            try:
                transport.auth_publickey(username, key)
                print('... success!')
                return
            except paramiko.SSHException as e:
                print('... failed!', e)

    def _filter_json(objects, key, value):
        pass

    def get_apache_logs(self):
        ssh = paramiko.Transport((config.APACHE_HOST, config.APACHE_SSH_PORT))
        ssh.start_client()
        self._ssh_agent_auth(ssh, config.APACHE_SSH_USER)

        if not ssh.is_authenticated():
            print("Authentication failed. Make sure that your key is added to SSH agent. If not, use ssh-add.")
            sys.exit(1)
        else:
            print("Authentication successful")

        #ssh.set_missing_host_key_policy(AllowAnythingPolicy())
        sftp = ssh.open_session()
        sftp = paramiko.SFTPClient.from_transport(ssh)
        sftp.chdir(config.APACHE_LOGS_FOLDER)
        for filename in sorted(sftp.listdir()):
            if filename.startswith(config.APACHE_LOGS_PREFIX):
                #print(filename)
                sftp.get(filename, self.apache_folder + filename)

        sftp.close()
        ssh.close()

    def get_empire_agents(self):
        header={'Content-Type': 'application/json'}
        url = '%s/api/agents?token=%s' % (config.EMPIRE_API_URL, config.EMPIRE_API_KEY)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url=url, headers=header, method='GET')
        res = urllib.request.urlopen(req, timeout=5, context=ctx)
        res_body = res.read()
        self.empire_agents = json.loads(res_body.decode("utf-8"))['agents']

    def get_msf_shells(self):
        pass

    def get_cobaltstrike_shells(self):
        pass

    def get_unique_email_opened(self):
        pass

    def get_unique_link_clicked(self):
        pass

    def get_unique_credentials_submit(self):
        pass

    def get_first_event_ts(self):
        pass

    def get_last_event_ts(self):
        pass

    def get_conversion_percentage(self):
        pass

    def extract_stats(self):
        self.stats['empire_agents_ct'] = len(self.empire_agents)

        self.stats['empire_agents_highpriv_ct'] = len([x for x in self.empire_agents if x['high_integrity'] == 1])

    def generate(self):
        print("Generating report.")

        print("Setting up folders")
        self._setup_out_folder()

        #print("Downloading apache logs")
        #self.get_apache_logs()

        print("Getting Empire Agents")
        self.get_empire_agents()

        print("Extracting stats")
        self.extract_stats()

        print("Report: ")
        print("  Empire Agents count: %s" % self.stats['empire_agents_ct'])
        print("  Empire Agents HighPriv count: %s" % self.stats['empire_agents_highpriv_ct'])
        print("")
