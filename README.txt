firebreak-box is a sample integration between the Box cloud storage
system and Palo Alto Networks' cloud-based WildFire malware analysis
environment.

It uses the Box Content API to access files in a user's cloud storage
folder tree, and the WildFire API to optionally submit files as
samples for analysis and malware verdict identification.

Python 3.x is required.

External modules:

  Requests HTTP library:
    http://docs.python-requests.org/en/latest/

  pan-python:
    https://github.com/kevinsteves/pan-python

Documentation:

  https://github.com/PaloAltoNetworks-BD/firebreak-box/blob/master/doc/boxoauth2.rst
  https://github.com/PaloAltoNetworks-BD/firebreak-box/blob/master/doc/firebreak-box.rst
