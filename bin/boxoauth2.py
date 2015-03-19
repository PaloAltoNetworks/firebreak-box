#!/usr/bin/env python

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

# https://developers.box.com/oauth/
# Box app configuration page: https://app.box.com/developers/services

import getopt
import os
import pprint
import sys
import uuid
import http.server
from urllib.parse import parse_qs

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import firebreak.secrets
import firebreak.box

secrets_filename = '.firebreak-box.json'
debug = 0
exit_status = 0
box = None
fbtag = None


def main():

    options = parse_opts()
    global debug, fbtag, box
    debug = options['debug']
    fbtag = options['fbtag']

    if options['client_id'] is None:
        print('client_id required', file=sys.stderr)
        sys.exit(1)

    if options['client_secret'] is None:
        try:
            options['client_secret'] = input('Enter Box client_secret: ')
        except EOFError:
            sys.exit(1)

    if debug > 1:
        print('client_secret:', options['client_secret'], file=sys.stderr)

    state = str(uuid.uuid4())

    try:
        box = firebreak.box.FbBox(debug=options['debug'])
    except firebreak.box.FbBoxError as e:
        print('firebreak.box.FbBoxError:', e, file=sys.stderr)
        sys.exit(1)

    uri = authorize_uri(options['client_id'], state,
                        box_login=options['box_login'])

    print('Paste this URI into your Web browser and authenticate to Box:\n')
    print(uri, '\n')

    authorization_code = run_http(options['client_id'],
                                  options['client_secret'], state)

    sys.exit(exit_status)


LISTEN_ADDR = 'localhost'
LISTEN_PORT = 8000


def authorize_uri(client_id, state, box_login=None):
    uri = ''
    uri += 'https://app.box.com/api/oauth2/authorize?'
    uri += 'response_type=code&'
    uri += 'client_id=%s&' % client_id
    if box_login is not None:
        uri += 'box_login=%s&' % box_login
    uri += 'state=%s&' % state
    redirect_uri = 'http://%s:%s' % (LISTEN_ADDR, LISTEN_PORT)
    uri += 'redirect_uri=%s' % redirect_uri

    return uri


def save_token(client_id, client_secret, refresh_token):
    try:
        secrets = firebreak.secrets.FbSecrets(filename=secrets_filename,
                                              tag=fbtag)
    except firebreak.secrets.FbSecretsError as e:
        print('firebreak.secrets.FbSecrets:', e, file=sys.stderr)
        return 1

    secrets.client_id = client_id
    secrets.client_secret = client_secret
    secrets.refresh_token = refresh_token
    try:
        secrets.save()
    except firebreak.secrets.FbSecretsError as e:
        print('firebreak.secrets.FbSecrets:', e, file=sys.stderr)
        return 1

    print('Saved secrets to %s' % secrets_filename)

    return 0


def refresh_token(client_id, client_secret, code):
    try:
        token = box.oauth2_refresh_token(client_id, client_secret, code)
    except firebreak.box.FbBoxError as e:
        print('firebreak.box.FbBox:', e, file=sys.stderr)
        if box.error is not None:
            print('error:', box.error, file=sys.stderr)
        if box.error_description is not None:
            print('error_description:', box.error, file=sys.stderr)
        return 1

    if token is not None:
        return(save_token(client_id, client_secret, token))

    print('Warning: box.oauth2_refresh_token(): no refresh_token',
          file=sys.stderr)
    return 1


def run_http(client_id, client_secret, state):
    class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        # override so we don't log request to stderr
        def log_message(self, *args):
            return

        def do_GET(self):
            global exit_status
            path = self.path
            path2 = path = path.split('?', 1)[1]
            qs = parse_qs(path2)

            if debug > 1:
                print('HTTP response:', path, file=sys.stderr)
                print('query string:', qs, file=sys.stderr)

            if 'code' in qs:
                if 'state' in qs and qs['state'][0] == state:
                    body = 'Authorization code received.'.encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_header('Content-Length', len(body))
                    self.end_headers()
                    self.wfile.write(body)
                    exit_status = refresh_token(client_id, client_secret,
                                                qs['code'][0])
                else:
                    s = 'Anti-forgery token invalid.'
                    body = s.encode()
                    self.send_response(401)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_header('Content-Length', len(body))
                    self.end_headers()
                    self.wfile.write(body)
                    print(s, file=sys.stderr)
                    exit_status = 1
            elif 'error' in qs:
                if 'error_description' in qs:
                    s = 'Error: %s.' % qs['error_description'][0]
                else:
                    s = 'Error: %s.' % repr(qs)
                body = s.encode()
                self.send_response(403)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
                print(s, file=sys.stderr)
                exit_status = 1
            else:
                s = repr(qs)
                body = s.encode()
                self.send_response(400)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
                print(s, file=sys.stderr)
                exit_status = 1

    server_address = (LISTEN_ADDR, LISTEN_PORT)
    httpd = http.server.HTTPServer(server_address,
                                   SimpleHTTPRequestHandler)
    httpd.handle_request()


def parse_opts():
    options = {
        'client_id': None,
        'client_secret': None,
        'box_login': None,
        'fbtag': None,
        'debug': 0,
        }

    short_options = ''
    long_options = ['help', 'debug=',
                    'client_id=', 'client_secret=', 'box_login=',
                    'fbtag=',
                    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   short_options,
                                   long_options)
    except getopt.GetoptError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if False:
            pass
        elif opt == '--client_id':
            options['client_id'] = arg
        elif opt == '--client_secret':
            options['client_secret'] = arg
        elif opt == '--box_login':
            options['box_login'] = arg
        elif opt == '--fbtag':
            options['fbtag'] = arg
        elif opt == '--debug':
            try:
                options['debug'] = int(arg)
                if options['debug'] < 0:
                    raise ValueError
            except ValueError:
                print('Invalid debug:', arg, file=sys.stderr)
                sys.exit(1)
            if options['debug'] > 3:
                print('Maximum debug level is 3', file=sys.stderr)
                sys.exit(1)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    if options['debug'] > 2:
        s = pprint.pformat(options, indent=4)
        print(s, file=sys.stderr)

    return options


def usage():
    usage = '''%s [options]
    --client_id id           client_id
    --client_secret secret   client_secret
    --box_login address      Box e-mail address
    --fbtag tagname          %s tagname
    --debug level            debug level (0-3)
    --help                   display usage
'''
    print(usage % (os.path.basename(sys.argv[0]), secrets_filename), end='')

if __name__ == '__main__':
    main()
