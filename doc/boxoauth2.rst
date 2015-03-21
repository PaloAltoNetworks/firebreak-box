..
 Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

============
boxoauth2.py
============

-------------------------------------------------------
perform OAuth 2.0 authorization code grant flow for Box
-------------------------------------------------------

NAME
====

 boxoauth2.py - perform OAuth 2.0 authorization code grant flow for Box

SYNOPSIS
========
::

 boxoauth2.py [options]
    --client_id id           client_id
    --client_secret secret   client_secret
    --box_login address      Box e-mail address
    --fbtag tagname         .firebreak-box.json tagname
    --debug level            debug level (0-3)
    --help                   display usage

DESCRIPTION
===========

 **boxoauth2.py** is a command line client program which uses the
 OAuth 2.0 authorization code grant flow to obtain an *access_token*
 and *refresh_token* for a Box application.

 The options are:

 ``--client_id`` *id*
  Specify the OAuth 2.0 *client_id* for a Box application.

 ``--client_secret`` *secret*
  Specify the OAuth 2.0 *client_secret* for a Box application.

 ``--box_login`` *address*
  Specify the Box login e-mail address.  This is optional and if
  not specified can be entered on the Box customer login page.

 ``--fbtag`` *tagname*
  Specify tagname for the .firebreakrc file.

 ``--debug`` *level*
  Enable debugging.
  *level* is an integer in the range 0-3; 0 specifies no
  debugging and 3 specifies maximum debugging.

 ``--help``
  Display **boxoauth2.py** command options.

Create a Box Application
------------------------

 Before you can use the Box API to access your cloud storage tree you
 need to create an application for content API access at
 https://app.box.com/developers/services.  This will provide you with
 a *client_id* and *client_secret* that will be used to generate a
 *refresh_token*.  The *refresh_token* is used to generate a new
 *access_token* to use in API requests.

.firebreak-box.json File
------------------------

 The *client_id*, *client_secret* and *refresh_token* are saved
 in the file ``.firebreak-box.json`` and can be referenced by a *tagname*
 which is *default* by default.

 A single Box application can be used to obtain a *refresh_token* for
 multiple Box accounts.  These accounts are identified by the
 *tagname*.

Authentication Flow
-------------------

 From the shell run **boxoauth2.py** specifying the required
 **--client_id** and **--client_secret** options.  You will be provided
 with a URI to paste into a web browser on the same host.

 **boxoauth2.py** will then listen for HTTP requests on
 http://localhost:8000.  After you authenticate to Box and grant
 access to your application an HTTP request will be received
 containing an authorization code which is used to obtain a
 *refresh_token*.

FILES
=====

 ``.firebreak-box.json``
  secrets file.

EXIT STATUS
===========

 **boxoauth2.rst** exits with 0 on success and 1 if an error occurs.

EXAMPLES
========

 Add secrets to .firebreak-box.json with tag panw.
 ::

  $ boxoauth2.py --client_id q8kzqmibvkm8qisb7y2gwrcjhxzliof5 \
  > --client_secret 4iFZ2gzsWMBNqx2NMLyo9yvnMookpBwy --fbtag panw
  Paste this URI into your Web browser and authenticate to Box:

  https://app.box.com/api/oauth2/authorize?response_type=code&client_id=q8kzqmibvkm8qisb7y2gwrcjhxzliof5&state=c9e4699a-da76-4a09-823f-669eccalhost:8000 

  Saved secrets to .firebreak-box.json

 View secrets.
 ::

  $ cat .firebreak-box.json 
  {
    "panw": {
      "refresh_token": "SQnPJdIJMKqPuwNvslBxHMUfhhARlcEcmW53xA9SqhMD2Zh6k4dIw0sp55nYavMq",
      "client_secret": "4iFZ2gzsWMBNqx2NMLyo9yvnMookpBwy",
      "client_id": "q8kzqmibvkm8qisb7y2gwrcjhxzliof5"
    }
  }
 
SEE ALSO
========

 firebreak-box.py

 How applications connect to Box using OAuth 2.0
  https://developers.box.com/oauth/

 Configure Box applications
  https://app.box.com/developers/services


AUTHORS
=======

 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
