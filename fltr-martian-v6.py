#!/usr/bin/python 
# IPv6 bogons RPSL object updater
# Written by Job Snijders <job@snijders-it.nl> in June 2012

import sys
import time, datetime, pytz
import ipaddr
import gnupg
import smtplib
from email.mime.text import MIMEText

# todo:
#    - do whois on current object and compare how much it differs from new one
# whois code: http://code.activestate.com/recipes/577364-whois-client/


print "+--------------------------------------------------------------------------+"
print "+ IPv6 Martian updater:"
print "+--------------------------------------------------------------------------+"

raw_prefixes = []

try:
    print 'progress: opening list...'
    with open('fltr-martian-v6.list', 'r') as f:
        for line in f:
            raw_prefixes.append(line.strip())
except:
    print 'error: file could not be opened'
    sys.exit(1)

utc = pytz.timezone("UTC")
unixtimestamp = str(int(time.time()))
timestamp = str(datetime.datetime.now(tz=utc))
timestamp = unixtimestamp + ' - ' + timestamp
print 'timestamp: ' + timestamp 

# check if is valid:
#   - contains at least 10 entries

amount = len(raw_prefixes)
if amount < 10:
    print "error: we expect more then 10 prefixes"
    sys.exit(1)
else:
    print "pass: seems we have enough prefixes"

# check for some prefixes
for line in raw_prefixes:
    try:
        if '2001:db8::/32' in line:
            print "pass: 2001:db8::/32 is in the list"
            break
    except:
        print "error: the list seems corrupt, 2001:db8::/32 is missing"
        sys.exit(1)

#   - are valid ipv6 prefixes and copy them to new list
valid_prefixes = []
for line in raw_prefixes:
    try:
        prefix = line.split("^")[0]
        if ipaddr.IPv6Network(prefix):
            valid_prefixes.append(line)
    except ValueError:
        print 'entry is not valid: %s' % prefix
        pass

# get last entry and remove the comma

formatted_prefixes = '\n    '.join(valid_prefixes)

# construct object
# RPSL object: 
header = """filter-set: fltr-martian-v6
descr: Current IPv6 martians
mp-filter: {
    """

footer = """
    }
remarks: timestamp: """ + timestamp + """
remarks: the following sources have been used:
    www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xml
    www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml
remarks: this object is manually maintained 
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
    print signed_rpslobject
    s.sendmail('job@snijders-it.nl', 'auto-dbm@ripe.net', msg.as_string())
    s.quit()
    print "pass: sent the email succesfully to the MTA"
    print "done: a new version has been uploaded"
except: 
    print "error: Unable to send email. Error: %s" % str(e)
    sys.exit(1)

