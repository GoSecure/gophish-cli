#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Class to test harvested usernames and passwords on a Outlook Web Access (OWA)

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

from exchangelib import DELEGATE, IMPERSONATION, Account, Credentials, \
    EWSDateTime, EWSTimeZone, Configuration, NTLM, CalendarItem, Message, \
    Mailbox, Attendee, Q
from exchangelib.folders import Calendar, ExtendedProperty, FileAttachment, ItemAttachment, \
    HTMLBody

import signal
import time

import logging

def test_request(arg=None):
    """Your http request."""
    time.sleep(2)
    return arg

class Timeout():
    """Timeout class using ALARM signal."""
    class Timeout(Exception):
        pass

    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)    # disable alarm

    def raise_timeout(self, *args):
        raise Timeout.Timeout()

class OwaCredsTester():

    def __init__(self, creds_list, domain, server, autodiscover=False, timeout=2,
                 verbose=True):
        self.creds_list = creds_list
        self.domain = domain
        self.server = server
        self.autodiscover=autodiscover
        self.timeout = timeout
        self.verbose = verbose

        # This is a temporary hack because the library print too much
        # unwanted details
        logging.disable(logging.CRITICAL)

    def _sanitize_username(self, username):
        # If username contains a \, take only the last part
        # Example: DOMAIN\user1 become user1
        if '\\' in username:
            a = username.split('\\')
            if len(a) > 1:
                s = a[-1]
            else:
                s = None
            return s

        # Ignore empty or very small usernames
        if len(username) < 3:
            return None

        # We force the use of our domain as people could do typo or write pure shit.
        # TODO: Make this behavior optional as some companies have multiple domains.
        return '%s\\%s' % (self.domain, username)

    def _sanitize_password(self, password):
        # Ignore empty or very small passwords
        if len(password) < 5:
            return None

        return password

    def _test_login_time_based(self, email, username, password):
        try:
            with Timeout(self.timeout):
                config = Configuration(
                    server=self.server,
                    credentials=Credentials(username=username, password=password),
                    auth_type=NTLM
                )
#                account = Account(primary_smtp_address=email, config=config,
#                 access_type=DELEGATE)
                return True
        except Timeout.Timeout:
            return False

    # Autodiscover
    # NOT TESTED
#   def _test_login_time_based_ad(self, email, user, pass):
#        credentials = Credentials(username='some_name', password='some_pass')
#        
#        # If your credentials have been given impersonation access to the target account, use
#        # access_type=IMPERSONATION
#        account = Account(primary_smtp_address='email@example.com', credentials=credentials,
#                          autodiscover=True, access_type=DELEGATE)

    def test_logins(self):
        tested_usernames = []   # Keep a track of tested usernames to avoid
                                # testing twice and eventually lock accounts.
        for creds in self.creds_list:
            username = self._sanitize_username(creds.username)
            password = self._sanitize_password(creds.password)
            if username is not None and password is not None:
                if not (username.lower() in tested_usernames):
                    #print('Testing: %s - %s - %s' % (creds.email,username,creds.password))
                    valid = self._test_login_time_based(creds.email, username, password)
                    if self.verbose:
                        if valid:
                            print('%s - %s: Successful login' % (username, password))
                        else:
                            print('%s - %s: Failed login' % (username, password))
                    tested_usernames.append(username.lower())
                else:
                    print('Username already tested: %s. Skipping.' % username)
            else:
                print('Invalid username or password: (%s - %s). Skipping.' % (username,password))


