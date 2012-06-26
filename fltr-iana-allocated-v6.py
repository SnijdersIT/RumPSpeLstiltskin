#!/usr/bin/python 
# IPv6 RPSL object updater
# Written by Job Snijders <job@snijders-it.nl> in June 2012

configuration = { 'email_from': 'job@snijders-it.nl',
    'filtername': 'AS15562:fltr-iana-allocated-v6',
    'email_to': 'auto-dbm@ripe.net',
    'gpg_keyid': 'C46D1B1C',
    'mnt_by': 'SNIJDERS-ROBOT-MNT',
    'admin_c': 'JWJS1-RIPE',
    'tech_c': 'JWJS1-RIPE',
    'org': 'ORG-SNIJ1-RIPE', 
    'gpg_homedir': '/home/job/.gnupg' }

import sys
import urllib2
from BeautifulSoup import BeautifulStoneSoup
import datetime, pytz, time
import ipaddr
import gnupg
import smtplib
from email.mime.text import MIMEText

# todo:
#    - do whois on current object and compare how much it differs from new one
# whois code: http://code.activestate.com/recipes/577364-whois-client/


print "+--------------------------------------------------------------------------+"
print "+ IPv6 IANA Allocated updater:"
print """+ This program will attempt to fetch up2date allocations list from IANA,
+ parse it, sign it, upload it to the RIPE IRR DB."""
print "+--------------------------------------------------------------------------+"

try:
    print 'progress: dowloading list...'
    f = urllib2.urlopen('http://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml')
except:
    print 'error: downloading prefix list failed'
    sys.exit(1)

utc = pytz.timezone("UTC")
unixtimestamp = str(int(time.time()))
timestamp = str(datetime.datetime.now(tz=utc))
timestamp = unixtimestamp + ' - ' + timestamp                                   
print 'timestamp: ' + timestamp

# fetch all ALLOCATED entries
###
#<registry xmlns="http://www.iana.org/assignments" id="ipv6-unicast-address-assignments">
#  <title>IPv6 Global Unicast Address Assignments</title>
#   <updated>2012-05-30</updated>
#      <description>The allocation of Internet Protocol version 6 (IPv6) unicast address space 
#      </description>
#      <note>The assignable Global Unicast Address space is defined in... 
#      </note>
#      <record date="1999-07-01">
#           <prefix>2001:0000::/23</prefix>
#           <description>IANA</description>
#           <whois>whois.iana.org</whois>
#           <status>ALLOCATED</status>
#           <xref type="note" data="1"/>
#      </record>
###
valid_prefixes = []

registry = BeautifulStoneSoup(f)
iana_stamp = registry.updated.contents[0]
for record in registry('record'):
    if record.status.contents[0] == 'ALLOCATED':
        prefix = record.prefix.contents[0]
        description = record.description.contents[0]
        date = record['date']
        if prefix  == '2001:4600::/23':
            found_magic_prefix = True
        try:
            if ipaddr.IPv6Network(prefix):
                new_entry = { 'prefix': prefix, 'descr': description, 'date': date }
                valid_prefixes.append(new_entry)
        except ValueError:
            print 'entry is not valid: %s' % record.prefix.contents[0]
            pass

amount = len(valid_prefixes)
if amount < 30 :
    print "error: we expect more than 40 prefixes"
    sys.exit(1)
else:
    print "pass: seems we have enough prefixes"

#   - contains 2001:4600::/23
if found_magic_prefix is True:
    print "pass: 2001:4600::/23 is in the list"
else:
    print "error: the list seems corrupt, 2001:4600::/23 is missing"
    sys.exit(1)

# loop through all the valid entries
# add some RPSL suger (we accept up to /16 and no smaller than /48)
# make sure the last entry doesn't end with a comma
formatted_prefixes = str()
networksize = "^16-48"
for filter_entry in valid_prefixes:
    if filter_entry is not valid_prefixes[-1]:
        string = "\t%s%s,\t# %s - %s\n" % (filter_entry['prefix'], networksize, filter_entry['descr'], filter_entry['date']) 
        formatted_prefixes += string
    else:
        string = "\t%s%s\t# %s - %s\n" % (filter_entry['prefix'], networksize, filter_entry['descr'], filter_entry['date']) 
        formatted_prefixes += string
 
# construct object
# RPSL object: 
header = """filter-set: """ + configuration['filtername'] + """
descr: All IPv6 prefixes IANA has allocated to the RIRs
mp-filter: {
    """

footer = """ }
remarks: last IANA update: """ + iana_stamp + """
remarks: filter generated: """ + timestamp + """
remarks: source www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml
remarks: this object is automatically updated the first day of every month
org: """ + configuration['org'] + """
tech-c: """ + configuration['tech_c'] + """
admin-c: """ + configuration['admin_c'] + """
mnt-by: """ + configuration['mnt_by'] + """
changed: """ + configuration['email_from'] + """
source: RIPE"""

rpslobject = header + formatted_prefixes + footer

# sign with PGPKEY-C46D1B1C on irime
gpg = gnupg.GPG(gnupghome=configuration['gpg_homedir'])
try:
    signed_rpslobject = str(gpg.sign(rpslobject,keyid=configuration['gpg_keyid'],clearsign=True))
    print "pass: signed the new object"
except:
    print "error: something went wrong with signing"
    sys.exit(1)

# email to auto-dbm@ripe.net
msg = MIMEText(signed_rpslobject, 'plain')
msg['Subject'] = 'IPv6 Bogons: %s' % timestamp
msg['From'] = configuration['email_from']
msg['To'] = configuration['email_to']
s = smtplib.SMTP('localhost')
try:
    print signed_rpslobject
    s.sendmail(configuration['email_from'], configuration['email_to'], msg.as_string())
    s.quit()
    print "pass: sent the email succesfully to the MTA"
    print "done: a new version has been uploaded"
except: 
    print "error: Unable to send email. Error: %s" % str(e)
    sys.exit(1)

