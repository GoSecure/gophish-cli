#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Class to test juniper authentication.

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

from urllib.request import urlopen
from urllib.parse import urlencode
import urllib.error

from modules.creds import WebCredsTester

class JuniperCredsTester(WebCredsTester):

    def __init__(self, creds_list, server, uri, domain, realm, verify_tls=True,
                    debug=False):
        super(JuniperCredsTester, self).__init__(creds_list, server, uri,
                verify_tls, debug=debug)
        self.domain = domain
        self.realm = realm

    def _test_login(self, username, password, realm):
        self.cj.clear_session_cookies()

        # TODO: Get realm directly from the login page.
        data = urlencode({'username': username, 'password': password, 
                        'realm': realm, 'btnSubmit': 'Sign In - Connexion'}).encode('UTF-8')

        url = 'https://%s%s' % (self.server,self.uri)
        #print('URL: %s' % url)

        try:
            response = urlopen(url, data=data, timeout=2)

            if self.debug:
                print(response.info())

            # According to my tests, three cookies are obtained when successful
            # login and that there is no current session
            # 
            # DSASSERTREF=x; path=/; expires=Thu, 01 Jan 1970 22:00:00 GMT; secure
            # DSID=d4f163fb7181541234aa8b170bb1913e; path=/; secure
            # DSFirstAccess=1487947220; path=/; secure
            # 
            # Here we will only check for DSID.
            # 
            dsid_cookie = self._get_cookie('DSID')
            if dsid_cookie is not None:
                return True

            # A redirection to a user confirmation page also means successful login.
            # Ex: 
            #location: https://vpn.example.com/dana-na/auth/url/welcome.cgi
            #           ?p=user-confirm&id=state_29c26b3530e9e540ae3e961bcb612134
            # 
            # Here, we must analyze the location field.
            #
            headers = response.info()
            if 'location' in headers \
              and 'welcome.cgi?p=user-confirm' in headers['location']:
                print('%s is currently connected.' % username)
                return True

            return False

        except urllib.error.HTTPError as e:
            # If return code is 500, consider it as a failure
            # but warn the user.
            if e.code == 500:
                print('Warning: Got a 500 response. Something went wrong.')
                return False
            else:
                print(e)

    def test_logins(self):
        tested_usernames = []   # Keep a track of tested usernames to avoid
                                # testing twice and eventually lock accounts.
        for creds in self.creds_list:
            username = self._sanitize_username(creds.username)
            password = self._sanitize_password(creds.password)
            if username is not None and password is not None:
                username = '%s\\%s' % (self.domain, username)
                if not (username.lower() in tested_usernames):
                    #print('Testing: %s - %s - %s' % (username,creds.password))
                    valid = self._test_login(username, password, self.realm)
                    self._print_login_result(valid, username, password)
                    tested_usernames.append(username.lower())
                else:
                    print('Username already tested: %s. Skipping.' % username)
            else:
                print('Invalid username or password: (%s - %s). Skipping.' % (username,password))


