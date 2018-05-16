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
import re
import ssl
import time
import json
import config
import pytz
import logging
import datetime
import dateutil.parser
import paramiko
import sendgrid
import urllib.request
import apache_log_parser
from prettytable import PrettyTable

BROWSER_MSG = ['Email Opened', 'Clicked Link', 'Submitted Data']

logger = logging.getLogger('gophish-cli')

class GophishReporter():
    timeline = None
    results = None
    empire_agents = None
    excluded_ip = []
    stats = {}

    out_folder = config.WORKING_DIR + 'report_%s/' % time.strftime("%Y%m%d-%H%M%S")
    apache_folder = out_folder + 'apache_logs/'

    # Flags to easily enable/disable features.
    enable_apache = True
    enable_sendgrid = True
    enable_empire = False
    enable_msf = False
    enable_cobalt = False

    def __init__(self, timeline, results):
        self.timeline = timeline
        self.results = results
        self.excluded_ip = config.EXCLUDED_IP
        self.timezone = pytz.timezone(config.GOPHISH_TIMEZONE)

    def _setup_out_folder(self):
        if not os.path.exists(self.out_folder):
            logger.debug("Creating folder: %s" % self.out_folder)
            os.makedirs(self.out_folder)

        if not os.path.exists(self.apache_folder):
            logger.debug("Creating folder: %s" % self.apache_folder)
            os.makedirs(self.apache_folder)

    def _ssh_agent_auth(self, transport, username):
        """
        Attempt to authenticate to the given transport using any of the private
        keys available from an SSH agent
        """
   
        logger.debug('[SSH] Attempting to authenticate')
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if len(agent_keys) == 0:
            return
    
        for key in agent_keys:
            logger.debug('[SSH] Trying ssh-agent key %s' % key.get_fingerprint().hex())
            try:
                transport.auth_publickey(username, key)
                logger.debug('[SSH]... success!')
                return
            except paramiko.SSHException as e:
                logger.debug('[SSH]... failed!', e)

    # Extract specific keys and return a list of their values.
    # Useful to extract empire unique users, workstations or operating systems
    def _json_get_unique_key(self, json_obj, key):
        return list(set([obj[key] for obj in json_obj]))

    def _json_get_count_key(self, json_obj, key):
        d = dict()
        for obj in json_obj:
            key_value = obj[key]
            d[key_value] = d.get(key_value, 0) + 1
        return d

    def _get_timeline_unique_key(self, key):
        return list(set([getattr(obj,key) for obj in self.timeline]))

    def _get_timeline_key_count(self, key):
        d = dict()
        for obj in self.timeline:
            key_value = getattr(obj,key)
            d[key_value] = d.get(key_value, 0) + 1
        return d

    def _get_results_unique_key(self, key):
        return list(set([getattr(obj,key) for obj in self.results]))

    def _get_results_key_count(self, key):
        d = dict()
        for obj in self.results:
            key_value = getattr(obj,key)
            d[key_value] = d.get(key_value, 0) + 1
        return d

    def _get_apache_key_count(self, key):
        d = dict()
        line_parser = apache_log_parser.make_parser(config.APACHE_LOGS_FORMAT)
        for log_line in self.apache_malware_dl:
            log_line_data = line_parser(log_line)
            key_value = log_line_data[key]
            d[key_value] = d.get(key_value, 0) + 1
        return d

    def _grep_files(self, path, search):
        res = []
        for root, dirs, fnames in os.walk(path):
            for fname in fnames:
                filepath = os.path.join(root, fname)
                with open(filepath, 'r', encoding = "ISO-8859-1") as f:
                    for line in f:
                        if search in line:
                            res.append(line)
        return res

    def get_apache_logs(self):
        ssh = paramiko.Transport((config.APACHE_HOST, config.APACHE_SSH_PORT))
        ssh.start_client()
        self._ssh_agent_auth(ssh, config.APACHE_SSH_USER)

        if not ssh.is_authenticated():
            logger.error("[SSH] Authentication failed. Make sure that your key is added to SSH agent. If not, use ssh-add.")
            sys.exit(1)
        else:
            logger.debug("[SSH] Authentication successful")

        #ssh.set_missing_host_key_policy(AllowAnythingPolicy())
        sftp = ssh.open_session()
        sftp = paramiko.SFTPClient.from_transport(ssh)
        logger.debug('[SSH] Changing directory: %s' % config.APACHE_LOGS_FOLDER)
        sftp.chdir(config.APACHE_LOGS_FOLDER)
        for filename in sorted(sftp.listdir()):
            if filename.startswith(config.APACHE_LOGS_PREFIX):
                logger.debug('[SSH] Downloading: %s' % filename)
                sftp.get(filename, self.apache_folder + filename)

        sftp.close()
        ssh.close()

        # TODO: Unzip *.gz 
        self.apache_malware_dl = self._grep_files(self.apache_folder, config.APACHE_MALWARE_NAME)
        logger.debug('  Got %s malware download' % len(self.apache_malware_dl))

    def get_empire_agents(self):
        header={'Content-Type': 'application/json'}
        url = '%s/api/agents?token=%s' % (config.EMPIRE_API_URL, config.EMPIRE_API_KEY)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url=url, headers=header, method='GET')
        res = urllib.request.urlopen(req, timeout=5, context=ctx)
        res_body = res.read()
        self.empire_agents = json.loads(res_body.decode('utf-8'))['agents']
        logger.debug('  Got %s agents' % len(self.empire_agents))

    def get_sendgrid_stats(self):
        sg = sendgrid.SendGridAPIClient(apikey=config.SENDGRID_API_KEY)
        start_date = self.get_first_event_ts().strftime('%Y-%m-%d')
        params = {'aggregated_by': 'day', 'limit': 1, 'start_date': start_date, 'end_date': start_date, 'offset': 1}
        response = sg.client.stats.get(query_params=params)
        if response.status_code == 200:
            self.sendgrid_stats = json.loads(response.body.decode('utf-8'))[0]['stats'][0]['metrics']
        else:
            self.sendgrid_stats = []

    def get_msf_shells(self):
        pass

    def get_cobaltstrike_shells(self):
        pass

    def get_first_event_ts(self):
        return dateutil.parser.parse(self.timeline[0].time).astimezone(self.timezone)

    def get_last_event_ts(self):
        return dateutil.parser.parse(self.timeline[-1].time).astimezone(self.timezone)

    def extract_gophish_stats(self):
        self.stats['first_event_ts'] = self.get_first_event_ts().strftime("%Y-%m-%d %H:%M:%S")
        self.stats['last_event_ts'] = self.get_last_event_ts().strftime("%Y-%m-%d %H:%M:%S")

        self.stats['email_sent_ct'] = len([x.email for x in self.timeline if x.message == 'Email Sent'])
        self.stats['email_opened_ct'] = len([x.email for x in self.timeline if x.message == 'Email Opened'])
        self.stats['clicked_link_ct'] = len([x.email for x in self.timeline if x.message == 'Clicked Link'])
        self.stats['submitted_data_ct'] = len([x.email for x in self.timeline if x.message == 'Submitted Data'])

        self.stats['unique_email_opened_ct'] = len(list(set([x.email for x in self.timeline if x.message == 'Email Opened'])))
        self.stats['unique_clicked_link_ct'] = len(list(set([x.email for x in self.timeline if x.message == 'Clicked Link'])))
        self.stats['unique_submitted_data_ct'] = len(list(set([x.email for x in self.timeline if x.message == 'Submitted Data'])))

        # source IP
        for i in range(0, len(self.timeline)):
            if self.timeline[i].message in BROWSER_MSG and type(self.timeline[i].details) is dict:
                self.timeline[i].source_ip = self.timeline[i].details['browser']['address']
            else:
                self.timeline[i].source_ip = None
        self.stats['source_ip'] = self._get_timeline_key_count('source_ip')
        
    def extract_apache_stats(self):
        self.stats['apache_malware_dl_ct'] = len(self.apache_malware_dl)
        self.stats['apache_source_ip'] = self._get_apache_key_count('remote_host')

    def extract_empire_stats(self):
        self.stats['empire_agents_ct'] = len(self.empire_agents)
        self.stats['empire_agents_highpriv_ct'] = len([x for x in self.empire_agents if x['high_integrity'] == 1])
        self.stats['empire_agents_unique_usernames_ct'] = len(self._json_get_unique_key(self.empire_agents, 'username'))
        self.stats['empire_agents_unique_hostnames_ct'] = len(self._json_get_unique_key(self.empire_agents, 'hostname'))

        self.stats['empire_os'] = self._json_get_count_key(self.empire_agents, 'os_details')
        self.stats['empire_source_ip'] = self._json_get_count_key(self.empire_agents, 'external_ip')

    def extract_msf_stats(self):
        self.stats['msf_agents_ct'] = 0
        self.stats['msf_agents_highpriv_ct'] = 0
        self.stats['msf_agents_unique_usernames_ct'] = 0
        self.stats['msf_agents_unique_hostnames_ct'] = 0

        self.stats['msf_os'] = []
        self.stats['msf_source_ip'] = []

    def extract_cobaltstrike_stats(self):
        self.stats['cs_agents_ct'] = 0
        self.stats['cs_agents_highpriv_ct'] = 0
        self.stats['cs_agents_unique_usernames_ct'] = 0
        self.stats['cs_agents_unique_hostnames_ct'] = 0

        self.stats['cs_os'] = []
        self.stats['cs_source_ip'] = []

    def extract_delivered_emails(self):
        pass

    def extract_conversion_stats(self):
        self.stats['conversion_receive_to_open'] = round(self.stats['email_opened_ct'] / self.stats['email_sent_ct'] * 100, 2)
        self.stats['conversion_email_to_click'] = round(self.stats['unique_clicked_link_ct'] / self.stats['email_opened_ct'] * 100, 2)
        self.stats['conversion_page_to_creds'] = round(self.stats['unique_submitted_data_ct'] / self.stats['unique_clicked_link_ct']  * 100, 2)

        if self.enable_apache and self.enable_empire:
            self.stats['conversion_dl_to_empire_exec'] = round(self.stats['empire_agents_unique_usernames_ct'] / \
                                                               self.stats['apache_malware_dl_ct']  * 100, 2)
        else:
            self.stats['conversion_dl_to_empire_exec'] = None

        if self.enable_apache and self.enable_msf: 
            self.stats['conversion_dl_to_msf_exec'] = round(self.stats['msf_agents_unique_usernames_ct'] / \
                                                            self.stats['apache_malware_dl_ct']  * 100, 2)
        else:
            self.stats['conversion_dl_to_msf_exec'] = None

        if self.enable_apache and self.enable_cobalt:
            self.stats['conversion_dl_to_cs_exec'] = round(self.stats['cs_agents_unique_usernames_ct'] / \
                                                           self.stats['apache_malware_dl_ct']  * 100, 2)
        else:
            self.stats['conversion_dl_to_cs_exec'] = None

    # Extract statistics of each position (often used as a department)
    # The objective is to extract stats based on departments.
    def extract_position_stats(self):
        self.stats['position'] = {}
        position_list = self._get_results_unique_key('position')

        for pos in position_list:
            position_results = [obj for obj in self.results if obj.position == pos]
            pos_total = len(position_results)
            if pos_total == 1:
                print(position_results)
            pos_scheduled = len([obj for obj in position_results if obj.status == 'Scheduled'])
            pos_email_sent = len([obj for obj in position_results if obj.status == 'Email Sent'])
            pos_email_open = len([obj for obj in position_results if obj.status == 'Email Opened'])
            pos_link_clicked = len([obj for obj in position_results if obj.status == 'Clicked Link'])
            pos_submitted_data = len([obj for obj in position_results if obj.status == 'Submitted Data'])

            self.stats['position'][pos] = {'total': pos_total, \
                                           'scheduled': pos_scheduled, \
                                           'email_sent': pos_email_sent, \
                                           'email_open': pos_email_open, \
                                           'link_clicked': pos_link_clicked, \
                                           'submitted_data': pos_submitted_data}

    def print_position_stats(self):
        title = ['Position', 'Scheduled', 'Email Sent', 'Email Open', \
                'Link Clicked', 'Submitted Data', 'Total']
        x = PrettyTable(title)
        x.align['Position'] = 'l'
        x.align['Scheduled'] = 'c'
        x.align['Email Sent'] = 'c' 
        x.align['Email Open'] = 'c' 
        x.align['Link Clicked'] = 'c' 
        x.align['Submitted Data'] = 'c' 
        x.align['Total'] = 'c' 
        x.padding_width = 1 
        x.max_width = 40

        position_list = self._get_results_unique_key('position')
        for pos in position_list:
            row = self.stats['position'][pos]
            x.add_row([ pos, row['scheduled'], row['email_sent'], \
                        row['email_open'], row['link_clicked'], \
                        row['submitted_data'], row['total'] ])
        print(x.get_string())

    def generate(self):
        logger.info("Generating report.")

        logger.info("Setting up folders")
        self._setup_out_folder()

        if self.enable_apache:
            logger.info("Downloading apache logs")
            self.get_apache_logs()

        if self.enable_sendgrid:
            logger.info("Getting Sendgrid Stats")
            self.get_sendgrid_stats()

        if self.enable_empire:
            logger.info("Getting Empire Agents")
            self.get_empire_agents()

        logger.info("Extracting stats")
        self.extract_gophish_stats()
        if self.enable_apache: self.extract_apache_stats()
        if self.enable_empire: self.extract_empire_stats()
        if self.enable_msf: self.extract_msf_stats()
        if self.enable_cobalt: self.extract_cobaltstrike_stats()
        self.extract_conversion_stats()
        self.extract_position_stats()

        logger.info("Printing Report")
        print("Raw Data: ")
        print("")
        print("  Timeline: ")
        print("    First Event: %s" % self.stats['first_event_ts'])
        print("    Last Event: %s" % self.stats['last_event_ts'])
        print("    Email sent: %s" % self.stats['email_sent_ct'])
        print("    Email opened: %s" % self.stats['email_opened_ct'])
        print("    Clicked Link: %s" % self.stats['clicked_link_ct'])
        print("    Submitted Data: %s" % self.stats['submitted_data_ct'])
        print("    Unique Email opened: %s" % self.stats['unique_email_opened_ct'])
        print("    Unique Clicked Link: %s" % self.stats['unique_clicked_link_ct'])
        print("    Unique Submitted Data: %s" % self.stats['unique_submitted_data_ct'])
        print("    Source IPs: ")
        for key, count in self.stats['source_ip'].items():
            print("      %s (%s)" % (key,count))
        print("")
        
        print("  Position stats:")
        self.print_position_stats()
        print("")

        if self.enable_sendgrid:
            print("  Sendgrid stats:")
            print("    Blocks: %s" % self.sendgrid_stats['blocks'])
            print("    Bounce Drops: %s" % self.sendgrid_stats['bounce_drops'])
            print("    Bounces: %s" % self.sendgrid_stats['bounces'])
            print("    Clicks: %s" % self.sendgrid_stats['clicks'])
            print("    Deffered: %s" % self.sendgrid_stats['deferred'])
            print("    Delivered: %s" % self.sendgrid_stats['delivered'])
            print("    Invalid Emails: %s" % self.sendgrid_stats['invalid_emails'])
            print("    Open: %s" % self.sendgrid_stats['opens'])
            print("    Processed: %s" % self.sendgrid_stats['processed'])
            print("    Requests: %s" % self.sendgrid_stats['requests'])
            print("    Spam Report Drops: %s" % self.sendgrid_stats['spam_report_drops'])
            print("    Spam Reports: %s" % self.sendgrid_stats['spam_reports'])
            print("    Unique Clicks: %s" % self.sendgrid_stats['unique_clicks'])
            print("    Unique Opens: %s" % self.sendgrid_stats['unique_opens'])
            print("    Subscribe Drops: %s" % self.sendgrid_stats['unsubscribe_drops'])
            print("    Unsubscribes: %s" % self.sendgrid_stats['unsubscribes'])
            print("")

        if self.enable_apache:
            print("  Apache: ")
            print("    Malware Download: %s" % self.stats['apache_malware_dl_ct'])
            print("    Source IPs: ")
            for key, count in self.stats['apache_source_ip'].items():
                print("      %s (%s)" % (key,count))
            print("")

        if self.enable_empire and self.stats['empire_agents_ct'] > 0:
            print("  Empire: ")
            print("    Agents count: %s" % self.stats['empire_agents_ct'])
            print("    Agents HighPriv count: %s" % self.stats['empire_agents_highpriv_ct'])
            print("    Unique Agents username count: %s" % self.stats['empire_agents_unique_usernames_ct'])
            print("    Unique Agents Hostnames count: %s" % self.stats['empire_agents_unique_hostnames_ct'])
            print("    OS Details: ")
            for key, count in self.stats['empire_os'].items():
                print("      %s (%s)" % (key,count))
            print("    Source IPs: ")
            for key, count in self.stats['empire_source_ip'].items():
                print("      %s (%s)" % (key,count))
            print("")

        if self.enable_msf and self.stats['msf_agents_ct'] > 0:
            print("  Metasploit: ")
            print("    Agents count: %s" % self.stats['msf_agents_ct'])
            print("    Agents HighPriv count: %s" % self.stats['msf_agents_highpriv_ct'])
            print("    Unique Agents username count: %s" % self.stats['msf_agents_unique_usernames_ct'])
            print("    Unique Agents Hostnames count: %s" % self.stats['msf_agents_unique_hostnames_ct'])
            print("    OS Details: ")
            for key, count in self.stats['msf_os'].items():
                print("      %s (%s)" % (key,count))
            print("    Source IPs: ")
            for key, count in self.stats['msf_source_ip'].items():
                print("      %s (%s)" % (key,count))
            print("")

        if self.enable_cobalt and self.stats['cs_agents_ct'] > 0:
            print("  Cobalt Strike: ")
            print("    Agents count: %s" % self.stats['cs_agents_ct'])
            print("    Agents HighPriv count: %s" % self.stats['cs_agents_highpriv_ct'])
            print("    Unique Agents username count: %s" % self.stats['cs_agents_unique_usernames_ct'])
            print("    Unique Agents Hostnames count: %s" % self.stats['cs_agents_unique_hostnames_ct'])
            print("    OS Details: ")
            for key, count in self.stats['cs_os'].items():
                print("      %s (%s)" % (key,count))
            print("    Source IPs: ")
            for key, count in self.stats['cs_source_ip'].items():
                print("      %s (%s)" % (key,count))
            print("")

        print("Analyzed Data: ")
        print("")
        print("  Conversion Percentage:")
        print("    Email Received (%s) -> Email Opened (%s): %s" % (self.stats['email_sent_ct'], 
                                                                    self.stats['email_opened_ct'], 
                                                                    self.stats['conversion_receive_to_open']))
        print("    Email Open (%s) -> Link Clicked (%s): %s" % (self.stats['email_opened_ct'], 
                                                                self.stats['unique_clicked_link_ct'],
                                                                self.stats['conversion_email_to_click']))
        print("    Page Visit (%s) -> Send Credentials (%s): %s" % (self.stats['unique_clicked_link_ct'], 
                                                                    self.stats['unique_submitted_data_ct'],
                                                                    self.stats['conversion_page_to_creds']))
        print("    Malware Download (%s) -> Malware Execution (%s) (Empire): %s" % (self.stats.get('apache_malware_dl_ct', None), 
                                                                                    self.stats.get('empire_agents_unique_usernames_ct', None),
                                                                                    self.stats.get('conversion_dl_to_empire_exec', None)))
        print("    Malware Download (%s) -> Malware Execution (%s) (Msf): %s" % (self.stats.get('apache_malware_dl_ct', None), 
                                                                                    self.stats.get('msf_agents_unique_usernames_ct', None),
                                                                                    self.stats.get('conversion_dl_to_msf_exec', None)))
        print("    Malware Download (%s) -> Malware Execution (%s) (Cobalt): %s" % (self.stats.get('apache_malware_dl_ct', None), 
                                                                                    self.stats.get('cs_agents_unique_usernames_ct', None),
                                                                                    self.stats.get('conversion_dl_to_cs_exec', None)))
        print("")
