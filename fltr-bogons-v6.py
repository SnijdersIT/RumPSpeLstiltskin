#!/usr/bin/python 
# IPv6 bogons RPSL object updater
# Written by Job Snijders <job@snijders-it.nl> in June 2012

import urllib2
import ipaddr
import gnupg
import smtplib
from email.mime.text import MIMEText

# todo:
#    - do whois on current object and compare how much it differs from new one
# whois code: http://code.activestate.com/recipes/577364-whois-client/


# download: www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
print "+--------------------------------------------------------------------------+"
print "+ IPv6 Bogon updater:"
print """+ This program will attempt to fetch up2date IPv6 Bogons list from cymru,
+ parse it, sign it, upload it to the RIPE IRR DB."""
print "+--------------------------------------------------------------------------+"

try:
    print 'progress: dowloading list...'
    f = urllib2.urlopen('http://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt')
except:
    print 'error: downloading prefix list failed'
    sys.exit(1)

raw_prefixes = f.read()
timestamp = raw_prefixes.split('\n', 1)[0][2:]

print 'timestamp: ' + timestamp

# dump prefixes into list, remove first and last line
raw_prefixes = raw_prefixes.split("\n")[1:-1]

# check if is valid:
#   - contains at least 50000 entries

amount = len(raw_prefixes)
if amount < 50000:
    print "error: we expect more then 50k prefixes"
    sys.exit(1)
else:
    print "pass: seems we have enough prefixes"

#   - contains 2000::/16 and 8000::/1
if '2000::/16' in raw_prefixes:
    print "pass: 2000::/16 is in the list"
else:
    print "error: the list seems corrupt, 2000::/16 is missing"
    sys.exit(1)
if '8000::/1' in raw_prefixes:
    print "pass: 8000::/1 is in the list"
else:
    print "error: the list seems corrupt, 8000::/1 is missing"
    sys.exit(1)

#   - are valid ipv6 prefixes and copy them to new list
valid_prefixes = []
for prefix in raw_prefixes:
    try:
        if ipaddr.IPv6Network(prefix):
            valid_prefixes.append(prefix + '^+,')
    except ValueError:
        print 'entry is not valid: %s' % prefix
        pass

# get last entry and remove the comma

last = valid_prefixes.pop()[:-1]
valid_prefixes.append(last)

formatted_prefixes = '\n    '.join(valid_prefixes)

# construct object
# RPSL object: 
header = """filter-set: fltr-bogons-v6
descr: All IPv6 bogons
mp-filter: {
    """

footer = """ }
remarks: """ + timestamp + """
remarks: source www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
remarks: this object is automatically updated every 12 hours
org: ORG-SNIJ1-RIPE
tech-c: JWJS1-RIPE
admin-c: JWJS1-RIPE
mnt-by: SNIJDERS-MNT
mnt-by: SNIJDERS-ROBOT-MNT
changed: job@snijders-it.nl
source: RIPE"""

rpslobject = header + formatted_prefixes + footer

# sign with PGPKEY-C46D1B1C on irime
gpg = gnupg.GPG(gnupghome='/home/job/.gnupg')
try:
    signed_rpslobject = str(gpg.sign(rpslobject,keyid='C46D1B1C',clearsign=True))
    print "pass: signed the new object"
except:
    print "error: something went wrong with signing"
    sys.exit(1)

# email to auto-dbm@ripe.net
msg = MIMEText(signed_rpslobject, 'plain')
msg['Subject'] = 'IPv6 Bogons: %s' % timestamp
msg['From'] = 'job@snijders-it.nl'
msg['To'] = 'auto-dbm@ripe.net'
s = smtplib.SMTP('localhost')
try:
#    print signed_rpslobject
    s.sendmail('job@snijders-it.nl', 'auto-dbm@ripe.net', msg.as_string())
    s.quit()
    print "pass: sent the email succesfully to the MTA"
    print "done: a new version has been uploaded"
except: 
    print "error: Unable to send email. Error: %s" % str(e)
    sys.exit(1)

