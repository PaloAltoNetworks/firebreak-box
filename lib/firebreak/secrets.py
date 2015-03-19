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

import json
import os

_search_path = ['.', '~']
_filename = '.secrets.json'
_default_tag = 'default'


class FbSecretsError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class FbSecrets:
    def __init__(self,
                 tag=None,
                 search_path=_search_path,
                 filename=_filename):
        self._tag = tag
        self.search_path = search_path
        self.filename = filename

        if self._tag is None:
            self._tag = _default_tag

        self._set_path()
        self._read()

    def _set_path(self):
        for basename in self.search_path:
            path = os.path.expanduser(basename)  # ~, ~user
            path = os.path.expandvars(path)      # $FOO
            path = os.path.join(path, self.filename)
            try:
                f = open(path, 'r')
            except IOError:
                continue
            self.path = path
            return

        self.path = os.path.join('.', self.filename)

        try:
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        except OSError as e:
            raise FbSecretsError('create %s: %s' % (path, e))

        os.close(fd)

    def _read(self):
        stat = os.stat(self.path)
        if stat.st_size == 0:
            self.secrets = {}
            return

        try:
            f = open(self.path, 'r')
        except IOError as e:
            raise FbSecretsError('open %s: %s' % (path, e))

        try:
            obj = json.load(f)
        except ValueError as e:
            f.close()
            raise FbSecretsError('json.load: %s: %s' % (self.path, e))
        if not (isinstance(obj, dict)):
            raise FbSecretsError('%s: not a dictionary' % self.path)

        self.secrets = obj
        f.close()

    def _write(self):
        try:
            f = open(self.path, 'w')
        except IOError as e:
            raise FbSecretsError('open %s: %s' % (path, e))

        try:
            json.dump(self.secrets, f, indent=2)
        except ValueError as e:
            f.close()
            raise FbSecretsError('json.dump: %s: %s' % (self.path, e))

        f.close()

    def save(self):
        self._write()

    def tag(self, tag):
        self._tag = tag

    def _getter(self, key):
        if self._tag in self.secrets and key in self.secrets[self._tag]:
            return self.secrets[self._tag][key]
        else:
            return None

    def _setter(self, key, x):
        if self._tag not in self.secrets:
            self.secrets[self._tag] = {}
        self.secrets[self._tag][key] = x

    @property
    def client_id(self):
        return self._getter('client_id')

    @client_id.setter
    def client_id(self, x):
        self._setter('client_id', x)

    @property
    def client_secret(self):
        return self._getter('client_secret')

    @client_secret.setter
    def client_secret(self, x):
        self._setter('client_secret', x)

    @property
    def refresh_token(self):
        return self._getter('refresh_token')

    @refresh_token.setter
    def refresh_token(self, x):
        self._setter('refresh_token', x)

if __name__ == '__main__':
    # python secrets.py [tag]
    import sys
    import uuid

    tag = None
    if len(sys.argv) > 1 and sys.argv[1]:
        tag = sys.argv[1]

    try:
        secrets = FbSecrets(tag=tag)
    except FbSecretsError as e:
        print('FbSecrets:', e, file=sys.stderr)
        sys.exit(1)

    print('refresh_token:', secrets.refresh_token)
    s = str(uuid.uuid4())
    secrets.refresh_token = s
    print('new refresh_token:', s)

    try:
        secrets.save()
    except FbSecretsError as e:
        print('FbSecrets:', e, file=sys.stderr)
        sys.exit(1)
