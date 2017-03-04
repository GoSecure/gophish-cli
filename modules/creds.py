#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Basic Credentials Testing class

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

from urllib.request import HTTPRedirectHandler,HTTPCookieProcessor,\
                            HTTPSHandler, HTTPErrorProcessor, \
                            build_opener, install_opener 
import http.cookiejar
import ssl

class NoRedirection(HTTPErrorProcessor):
  def http_response(self, request, response):
    return response
  https_response = http_response

class Credentials():
    def __init__(self, email=None, username=None, password=None):
        self.email = email
        self.username = username
        self.password = password
        self.is_valid = None

    def get_validity(self):
        if self.is_valid is None:
            return 'unknown'
        elif self.is_valid == True:
            return 'Success'
        else:
            return 'Failed'

    def to_list(self):
        return [self.email, self.username, self.password, self.get_validity()]

    def to_dict(self):
        return {'email': self.email,
                'username': self.username,
                'password': self.password,
                'is_valid': self.get_validity()}

class CredsTester(object):

    def __init__(self, creds_list, server, verbose=True, debug=False):
        self.creds_list = creds_list
        self.server = server
        self.verbose = verbose
        self.debug = debug

    def _sanitize_username(self, username):
        # If username contains a \, take only the last part
        # Example: DOMAIN\user1 become user1
        if '\\' in username:
            a = username.split('\\')
            if len(a) > 1:
                username = a[-1]
            else:
                username = None

        # Ignore empty or very small usernames
        if len(username) < 3:
            username = None

        return username

    def _sanitize_password(self, password):
        # Ignore empty or very small passwords
        if len(password) < 5:
            return None

        return password

    def _print_login_result(self, valid, username, password):
        if self.verbose:
            if valid:
                print('%s - %s - Successful login' % (username, password))
            else:
                print('%s - %s - Failed login' % (username, password))

    def print_results(self):
        creds_success = sum([1 for creds in self.creds_list if creds.is_valid])
        creds_fail = sum([1 for creds in self.creds_list if creds.is_valid == False])
        creds_unknown = sum([1 for creds in self.creds_list if creds.is_valid is None])
        print('[-] Test results: %s successful, %s fail and %s unknown (duplicate) out of %s.'
              % (creds_success, creds_fail, creds_unknown, len(self.creds_list)))

    def test_logins(self):
        pass

class WebCredsTester(CredsTester):
    def __init__(self, creds_list, server, uri='/', verify_tls=True, debug=False):
        super(WebCredsTester, self).__init__(creds_list, server, debug=debug)
        self.uri = uri
        self.verify_tls = verify_tls
        self._init_urllib()

    def _init_urllib(self):
        # Initialize a SSL context for all HTTPS calls
        if self.verify_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
        else: 
            context = ssl.create_default_context()  # Should we enforce TLS 1.1 here?
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Cookie Jar
        self.cj = http.cookiejar.CookieJar()

        # Debugging
        if self.debug:
            debuglevel=1
        else:
            debuglevel=0

        opener = build_opener(HTTPSHandler(debuglevel=debuglevel, context=context), \
                              HTTPCookieProcessor(self.cj), 
                              NoRedirection)
    
        install_opener(opener)

    def _get_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    # The actual login test, called for every pair of credentials
    def _test_login(self, username, password):
        return False

    # To test the list of credentials
    def test_logins(self):
        pass
