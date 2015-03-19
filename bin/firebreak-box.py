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

# firebreak: Fight fire with WildFire

import fnmatch
import getopt
import json
import os
import pprint
import sys
try:
    import requests
except ImportError:
    raise ValueError('Install Requests library: '
                     'http://docs.python-requests.org/')

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import firebreak.box
import firebreak.secrets

try:
    import pan.wfapi
    import pan.config
except ImportError:
    raise ValueError('Install pan-python: '
                     'https://github.com/kevinsteves/pan-python')

secrets_filename = '.firebreak-box.json'
options = None
wfapi = None


def main():
    global options, wfapi
    options = parse_opts()

    try:
        box = firebreak.box.FbBox(debug=options['debug'])
    except firebreak.box.FbBoxError as e:
        print('firebreak.box.FbBoxError:', e, file=sys.stderr)
        sys.exit(1)

    if options['access_token'] is not None:
        access_token = options['access_token']
    else:
        try:
            secrets = firebreak.secrets.FbSecrets(filename=secrets_filename,
                                                  tag=options['fbtag'])
        except firebreak.secrets.FbSecretsError as e:
            print('firebreak.secrets.FbSecrets:', e, file=sys.stderr)
            sys.exit(1)

        if (secrets.refresh_token is None):
            print('No refresh_token', file=sys.stderr)
            sys.exit(1)

        try:
            tokens = box.oauth2_access_token(secrets.client_id,
                                             secrets.client_secret,
                                             secrets.refresh_token)
        except firebreak.box.FbBoxError as e:
            print('firebreak.box.FbBoxError:', e, file=sys.stderr)
            sys.exit(1)

        if tokens is None:
            print("Can't get access_token from refresh_token",
                  file=sys.stderr)
            sys.exit(1)

        secrets.refresh_token = tokens[0]
        try:
            secrets.save()
        except firebreak.secrets.FbSecretsError as e:
            print('firebreak.secrets.FbSecrets:', e, file=sys.stderr)
            sys.exit(1)

        access_token = tokens[1]

    try:
        box = firebreak.box.FbBox(debug=options['debug'],
                                  access_token=access_token)
    except firebreak.box.FbBoxError as e:
        print('firebreak.box.FbBoxError:', e, file=sys.stderr)
        sys.exit(1)

    if options['submit']:
        try:
            wfapi = pan.wfapi.PanWFapi(tag=options['tag'])
        except pan.wfapi.PanWFapiError as msg:
            print('pan.wfapi.PanWFapi:', msg, file=sys.stderr)
            sys.exit(1)

    do_folder(box, 0)

    sys.exit(0)


def do_folder(box, id):
    req = get_folder(box, id)

    o = req.json()
    for entry in o['item_collection']['entries']:
        if options['debug'] > 1:
            print('type %s name "%s" id %s' %
                  (entry['type'], entry['name'], entry['id']), file=sys.stderr)
        if entry['type'] == 'folder':
            do_folder(box, entry['id'])
        elif entry['type'] == 'file':
            do_file(box, entry['id'])
        else:
            print('Unknown folder item: type %s name "%s" id %s' %
                  (entry['type'], entry['name'], entry['id']), file=sys.stderr)


def do_file(box, id):
    req = get_file(box, id)
    o = req.json()

    path = ''
    for entry in o['path_collection']['entries']:
        path += entry['name'] + '/'
    path += o['name']
    if options['match'] is None:
        pass
    elif not fnmatch.fnmatch(path, options['match']):
        return
    print('"%s" size %s' % (path, o['size']))
    req = get_file_content(box, id)
    if box.req.status_code == 302:
        url = box.req.headers['location']
        if options['debug'] > 1:
            print(url, file=sys.stderr)

        if options['submit']:
            wf_submit_file(path, url)


def get_folder(box, id):
    try:
        box.folders(id=id)
    except firebreak.box.FbBoxError as e:
        print('Error folder id', id, file=sys.stderr)
        print('firebreak.box.FbBoxError:', e, file=sys.stderr)

    if box.req.status_code == 200:
        if options['debug'] > 2:
            print(box.req.headers, file=sys.stderr)
            print(json.dumps(box.req.json(), indent=2), file=sys.stderr)
    else:
        print_error(box, 'folder', id)

    return box.req


def get_file(box, id):
    try:
        box.file(id=id)
    except firebreak.box.FbBoxError as e:
        print('Error file id', id, file=sys.stderr)
        print('firebreak.box.FbBoxError:', e, file=sys.stderr)

    if box.req.status_code == 200:
        if box.debug > 2:
            print(box.req.headers, file=sys.stderr)
            print(json.dumps(box.req.json(), indent=2))
    else:
        print_error(box, 'file', id)

    return box.req


def get_file_content(box, id):
    try:
        box.file_content(id=id)
    except firebreak.box.FbBoxError as e:
        print('Error file id', id, file=sys.stderr)
        print('firebreak.box.FbBoxError:', e, file=sys.stderr)

    if box.req.status_code == 302:
        if box.debug > 2:
            print(box.req.headers['location'], file=sys.stderr)
    else:
        print_error(box, 'file', id)

    return box.req


def print_error(box, what, id):
    print('Error %s %s' % (what, id), file=sys.stderr)
    print(box.req.status_code, box.req.reason, file=sys.stderr)
    if box.req.status_code in [401, 403]:
        if options['debug'] > 1:
            print(box.req.headers, file=sys.stderr)
        box.check_auth()
        if box.auth_error or box.auth_error_description:
            print('error: %s, error_description: %s' %
                  (box.auth_error, box.auth_error_description))

    sys.exit(1)


def wf_submit_file(path, url):
    try:
        wfapi.submit(url=url)
        if options['debug'] > 0:
            print_status(wfapi, 'submit')
            print_response(wfapi)
        print_upload_file_info(wfapi, path)
    except pan.wfapi.PanWFapiError as e:
        print_status(wfapi, 'submit', e)
        print_response(wfapi)


def print_status(wfapi, action, exception_msg=None):
    print(action, end='', file=sys.stderr)

    if exception_msg is not None:
        print(': %s' % exception_msg, end='', file=sys.stderr)
    else:
        if wfapi.http_code is not None:
            print(': %s' % wfapi.http_code, end='', file=sys.stderr)
        if wfapi.http_reason is not None:
            print(' %s' % wfapi.http_reason, end='', file=sys.stderr)

    print(' [', end='', file=sys.stderr)
    if wfapi.attachment is not None:
        print('attachment="%s"' % wfapi.attachment['filename'], end='',
              file=sys.stderr)
    else:
        body = True if wfapi.response_body is not None else False
        print('response_body=%s' % body, end='', file=sys.stderr)
        if wfapi.response_type is not None:
            print(' response_type=%s' % wfapi.response_type, end='',
                  file=sys.stderr)
        if body:
            print(' length=%d' % len(wfapi.response_body), end='',
                  file=sys.stderr)
    print(']', end='', file=sys.stderr)

    print(file=sys.stderr)


def xml_python(elem):
    try:
        conf = pan.config.PanConfig(config=elem)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    o = conf.python()
    return o


def print_upload_file_info(wfapi, path):
    if wfapi.xml_element_root is None:
        return

    indent = '    '
    elem = wfapi.xml_element_root
    o = xml_python(elem)

    if o:
        o2 = o['wildfire']['upload-file-info']
        filetype = o2['filetype']
        sha256 = o2['sha256']
    print('"%s" (%s) uploaded to WildFire' % (os.path.basename(path),
                                              filetype))
    print('%ssha256 %s' % (indent, sha256))

    try:
        wfapi.verdict(hash=sha256)
    except pan.wfapi.PanWFapiError as msg:
        print('pan.wfapi.PanWFapi:', msg, file=sys.stderr)
        return

    if wfapi.xml_element_root is None:
        return

    elem = wfapi.xml_element_root
    o = xml_python(elem)

    if o:
        o2 = o['wildfire']['get-verdict-info']
        result_sha256 = o2['sha256']
        try:
            verdict = int(o2['verdict'])
        except ValueError:
            print('Warning: verdict not int: %s' % os['verdict'],
                  file=sys.stderr)
            return

    if result_sha256 != sha256:
        print('Warning: %s != %s' % (result_sha256, sha256),
              file=sys.stderr)
        return

    if verdict in pan.wfapi.VERDICTS:
        x = pan.wfapi.VERDICTS[verdict]
        print('%sverdict %s' % (indent, x[0]))
    else:
        print('Warning: unknown verdict: %d' % verdict,
              file=sys.stderr)


def print_response(wfapi):
    if options['debug'] < 3:
        return

    if wfapi.response_body is not None:
        print(wfapi.response_body)

    if wfapi.xml_element_root is None:
        return

    elem = wfapi.xml_element_root

    try:
        conf = pan.config.PanConfig(config=elem)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:', msg, file=sys.stderr)
        sys.exit(1)

    d = conf.python()
    if d:
        print('var1 =', pprint.pformat(d))
        print(json.dumps(d, sort_keys=True, indent=2))


def parse_opts():
    options = {
        'access_token': None,
        'match': None,
        'tag': None,
        'fbtag': None,
        'submit': False,
        'debug': 0,
        }

    short_options = ''
    long_options = ['help', 'debug=',
                    'access_token=', 'match=', 'tag=', 'fbtag=', 'submit',
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
        elif opt == '--access_token':
            options['access_token'] = arg
        elif opt == '--match':
            options['match'] = arg
        elif opt == '--tag':
            options['tag'] = arg
        elif opt == '--fbtag':
            options['fbtag'] = arg
        elif opt == '--submit':
            options['submit'] = True
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
    --access_token token  Box OAuth2 access token
    --match pattern       process files matching pattern
    --tag tagname         .panrc tagname (WildFire api_key)
    --fbtag tagname       %s tagname (Box OAuth2)
    --submit              submit files to WildFire for analysis
    --debug level         debug level (0-3)
    --help                display usage
'''
    print(usage % (os.path.basename(sys.argv[0]), secrets_filename), end='')

if __name__ == '__main__':
    main()
