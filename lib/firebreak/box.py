#
# Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Life is like a box of malware--you never know what you're gonna get.

import sys

try:
    import requests
except ImportError:
    raise ValueError('Install requests library: '
                     'http://docs.python-requests.org/')


class FbBoxError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        if self.msg is None:
            return ''
        return self.msg

_API_URI = 'https://api.box.com/2.0/'


class FbBox:
    def __init__(self,
                 access_token=None,
                 debug=0):
        self.debug = debug
        self.access_token = access_token

        if access_token is not None:
            self._set_authorization()

    def _set_authorization(self):
        self.headers = {
            'authorization': 'Bearer ' + self.access_token,
        }

    def _clear_status(self):
        self.error = None
        self.error_description = None
        self.req = None

    def folders(self,
                id=None):
        self.req = None

        if self.access_token is None:
            raise FbBoxError('no access_token')
        if id is None:
            raise FbBoxError('missing id')

        uri = _API_URI + 'folders/' + str(id)

        try:
            r = requests.get(url=uri, headers=self.headers)
        except requests.exceptions.RequestException as e:
            raise FbBoxError(e)

        self.req = r

    def file(self,
             id=None):
        self.req = None

        if self.access_token is None:
            raise FbBoxError('no access_token')
        if id is None:
            raise FbBoxError('missing id')

        uri = _API_URI + 'files/' + str(id)

        try:
            r = requests.get(url=uri, headers=self.headers)
        except requests.exceptions.RequestException as e:
            raise FbBoxError(e)

        self.req = r

    def file_content(self,
                     id=None):
        if self.access_token is None:
            raise FbBoxError('no access_token')
        if id is None:
            raise FbBoxError('missing id')

        uri = _API_URI + 'files/' + str(id) + '/content'

        try:
            r = requests.get(url=uri, headers=self.headers,
                             allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise FbBoxError(e)

        self.req = r

    def check_auth(self):
        self.auth_error = None
        self.auth_error_description = None
        self.auth = self.req.headers.get('www-authenticate')
        if self.auth is None:
            return

        # XXX not robust
        fields = self.auth.split(', ')
        for field in fields:
            x = field.split('=', 1)
            if x[0] == 'error' and len(x) == 2:
                self.auth_error = x[1][1:-1]
            if x[0] == 'error_description' and len(x) == 2:
                self.auth_error_description = x[1][1:-1]

    # exchange authorization_code for refresh_token
    def oauth2_refresh_token(self, client_id, client_secret, code):
        uri = 'https://app.box.com/api/oauth2/token'

        query = {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
        }
        if self.debug > 0:
            print(query, file=sys.stderr)

        self._clear_status()
        try:
            r = requests.post(url=uri, data=query)
        except requests.exceptions.RequestException as e:
            raise FbBoxError(e)

        self.req = r

        o = r.json()

        if r.status_code == 200:
            if 'refresh_token' in o:
                return o['refresh_token']
            else:
                return None

        else:
            msg = 'Error: grant_type=authorization_code'
            if 'error' in o:
                self.error = o['error']
                if 'error_description' in o:
                    self.error_description = o['error_description']
            raise FbBoxError(msg)

    # exchange refresh_token for access_token and new refresh_token
    def oauth2_access_token(self, client_id, client_secret, refresh_token):
        uri = 'https://app.box.com/api/oauth2/token'

        query = {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
        }
        if self.debug > 0:
            print(query, file=sys.stderr)

        try:
            r = requests.post(url=uri, data=query)
        except requests.exceptions.RequestException as e:
            raise FbBoxError(e)

        self.req = r

        o = r.json()

        if r.status_code == 200:
            if 'refresh_token' in o and 'access_token' in o:
                return (o['refresh_token'], o['access_token'])
            else:
                return None

        else:
            msg = 'Error: grant_type=refresh_token'
            if 'error' in o:
                self.error = o['error']
                if 'error_description' in o:
                    self.error_description = o['error_description']
            raise FbBoxError(msg)
