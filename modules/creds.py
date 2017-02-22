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

class Credentials():
    def __init__(self, email=None, username=None, password=None):
        self.email = email
        self.username = username
        self.password = password

    def to_list(self):
        return [self.email, self.username, self.password]

    def to_dict(self):
        return {'email': self.email,
                'username': self.username,
                'password': self.password}

class CredsTester(object):

    def __init__(self, creds_list, server, verbose=True):
        self.creds_list = creds_list
        self.server = server
        self.verbose = verbose

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

    def test_logins(self):
        pass
