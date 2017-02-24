#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Class that test netscaler authentication.

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
                            HTTPHandler, HTTPSHandler, \
                            build_opener, install_opener, urlopen
from urllib.parse import urlencode
import urllib.error
import http.cookiejar
import ssl

from modules.creds import CredsTester

class NetscalerCredsTester(CredsTester):

    def __init__(self, creds_list, server, uri='/cgi/login',verify_tls=True):
        super(NetscalerCredsTester, self).__init__(creds_list, server)
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

        opener = build_opener(HTTPSHandler(context=context), \
                              HTTPHandler(), \
                              HTTPCookieProcessor(self.cj))
    
        install_opener(opener)

    def _get_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    # 
    # WARNING
    #
    # This is very experimental... (and ugly)
    #
    def _test_login(self, username, password):
        self.cj.clear_session_cookies()
        data = urlencode({'login': username, 'passwd': password}).encode('UTF-8')
        url = 'https://%s%s' % (self.server,self.uri)
        #print('URL: %s' % url)

        try:
            response = urlopen(url, data=data, timeout=2)

            # If the NSC_VPNERR cookie is set, an error occured.
            nsc_error_cookie = self._get_cookie('NSC_VPNERR')
            if nsc_error_cookie is not None:
                return False

            # If the returning code is not 500, it may be a 302 with 2 cookies.
            nsc_tmaa_cookie = self._get_cookie('NSC_TMAA')
            nsc_tmas_cookie = self._get_cookie('NSC_TMAS')
            if nsc_tmaa_cookie is not None \
                and nsc_tmas_cookie is not None:
                return True

            # Otherwise, consider failed login.
            return False

        except urllib.error.HTTPError as e:
            # In several case, a 500 means successful, meaning the login was successful
            # but the redirection (or else) failed.
            if e.code == 500:
                return True

    def test_logins(self):
        tested_usernames = []   # Keep a track of tested usernames to avoid
                                # testing twice and eventually lock accounts.
        for creds in self.creds_list:
            username = self._sanitize_username(creds.username)
            password = self._sanitize_password(creds.password)
            if username is not None and password is not None:
                if not (username.lower() in tested_usernames):
                    #print('Testing: %s - %s - %s' % (username,creds.password))
                    valid = self._test_login(username, password)
                    self._print_login_result(valid, username, password)
                    creds.is_valid = valid
                    tested_usernames.append(username.lower())
                else:
                    print('Username already tested: %s. Skipping.' % username)
            else:
                print('Invalid username or password: (%s - %s). Skipping.' % (username,password))

