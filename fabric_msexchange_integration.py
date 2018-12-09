#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" FortiSIEM , Security Fabric and Microsoft Exchange integration script

this is meant to be used by FortiSIEM to mitigate a zero day malware sent from within the organization 
The script leverages the identifies the user sending the malware and connects to its mailbox, locates the malicious email and extract the list of recipients.
open each recipient’s mailbox and delete the malicious email while sending an alert to the victim.
the script will sender active directory account can be disabled

Example:
        ./fabric_msexchange_integration incident.xml

Todo:
    * Quarantine a user if the email has been read, either through FortiClient or FortiGate

PS: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND

"""
__author__ = "Naili Mahdi"
__license__ = "GPL"
__version__ = "0.0.4"
__maintainer__ = "Naili Mahdi"
__status__ = "alpha"

from datetime import timedelta
from exchangelib import IMPERSONATION, Account, Credentials, Configuration, FileAttachment, NTLM, EWSDateTime, EWSTimeZone, Message, Mailbox
import os, sys, re, logging, base64, requests, ldap
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import xml.etree.ElementTree as xml

# uncomment this line below to turn on debug logs
#logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
logging.basicConfig(stream=sys.stderr, level=logging.CRITICAL)



ad_sys_user = 'sysagent'
ad_sys_password = base64.b64decode('your base 64 pass')


config = Configuration(
	server='X.X.X.X', #to be changed with AD IP
	credentials=Credentials(username='DOMAIN\\USER', password='PASS'),
	auth_type=NTLM,
	verify_ssl=False
) 

def disable_ad_account(domain_name,username, password,base_dn,lp_username):
	# Disable Active Directory User Account

	# Args:
	# 	domain_name (str)	: AD domain name :ex mydomain.com
	# 	username (str)		: admin account used for AD authentication
	# 	password (str)		: password for the admin account
	# 	base_dn (str)		: AD base DN (exp: DC=domain,DC=com)
	# 	lp_username (str)	: The AD username to be disabled (aka. compromised ID) 

	# Returns:
	# 	bool: The return value. True for success, False otherwise.

	LDAP_SERVER = 'ldap://X.X.X.X'	#to be changed with AD IP
	LDAP_USERNAME = username+'@'+domain_name
	attrs = ['memberOf']
	mod_acct = [(ldap.MOD_REPLACE, 'userAccountControl', '514')]

	try:
		# build a client
		ldap_client = ldap.initialize(LDAP_SERVER)
		# perform a synchronous bind
		ldap_client.set_option(ldap.OPT_REFERRALS,0)
		ldap_client.simple_bind_s(LDAP_USERNAME, password)
	except ldap.INVALID_CREDENTIALS:
		ldap_client.unbind()
		return 'Wrong username or password'
	except ldap.SERVER_DOWN:
		return 'AD server not awailable'
	
	# Change the account back to enabled
	try:
		user_results = ldap_client.search_s(base_dn, ldap.SCOPE_SUBTREE,'(&(sAMAccountName=' +lp_username +')(objectClass=person))',['distinguishedName'])
	 	user_dn = user_results[0][1]['distinguishedName'][0]
	except ldap.LDAPError, error_message:
		print "Error finding username: %s" % error_message
		return False
	try:
		ldap_client.modify_s(user_dn, mod_acct)
		logging.debug('disabling '+user_dn)
	except ldap.LDAPError, error_message:
		print "Error disabling user: %s" % error_message
		return False

def check_principal_email(domain_name,username, password,base_dn,lp_username):
	# returns the user principal email, this is required for EWS when the user has an alias, LDAP server IP has to be changed of course.

	# Args:
	#     domain_name (str)	: AD domain name :ex mydomain.com
	#     username (str)		: admin account used for AD authentication
	#     password (str)		: password for the admin account
	#     base_dn (str)		: AD base DN (exp: DC=domain,DC=com)
	#     lp_username (str)	: AD username to lookup the principal email @

	# Returns:
	#     principal email address for lp_username if successful or None if not.

	LDAP_SERVER = 'ldap://X.X.X.X'
	# fully qualified AD user name
	LDAP_USERNAME = username+'@'+domain_name
	# your password
	LDAP_PASSWORD = password
	attrs = ['memberOf']
	try:
		# build a client
		ldap_client = ldap.initialize(LDAP_SERVER)
		# perform a synchronous bind
		ldap_client.set_option(ldap.OPT_REFERRALS,0)
		ldap_client.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
	except ldap.INVALID_CREDENTIALS:
		ldap_client.unbind()
		return 'Wrong username or password'
	except ldap.SERVER_DOWN:
		return 'AD server unreachable'

	result = ldap_client.search_s(base_dn, ldap.SCOPE_SUBTREE,'(&(sAMAccountName='+lp_username+')(objectClass=*))',['proxyAddresses'])
	results = [entry for dn, entry in result if isinstance(entry, dict)]
	match = re.search(r'SMTP\:[\w\.-]+@[\w\.-]+', str(results))
	email = match.group(0).split(":")[1]
	ldap_client.unbind()
	if email is not None:
		return email
	else:
		return None


def xml_parser(fileName):
	# Parse incidents attributes from incident.xml 

	# Args:
	#     fileName (str)	: incident.xml file supplied by FortiSIEM at the time of execution as argv

	# Returns:
	#     returns : a dictionary of parsed incident attrutes  returns the user principal email, this is required for EWS when the user has an alias, LDAP server IP has to be changed of course.
	
	tree = xml.parse(fileName)
	root = tree.getroot()
	parsed_data = {}

	for element in root.iter(tag='entry'):
		if element.attrib['attribute'] == 'srcIpAddr':
			parsed_data['source_ip']=element.text
		elif element.attrib['attribute'] == 'user':
			parsed_data['sender_username']=element.text
		elif element.attrib['attribute'] =='domain':
			parsed_data['sender_domain']=element.text
		elif element.attrib['attribute'] =='fileName':
			parsed_data['malicious_file_name']=element.text

	for element in tree.findall('.//identityLocation/userDetail'):
		if element.find('email') is not None:
			#print element.find('email').text
			parsed_data['email'] = element.find('email').text

	return parsed_data


def find_malicious_email(sender_email,file_name):
	# identify the attributes of the email with was sent with the malicious attachment

	# Args:
	#     sender_email (str)	: the sender email address
	#     file_name (str)		: the attachment file name to identify the malicious email

	# Returns:
	#     two lists, sibjects of the infected emails, recipients of the infected email

	# TODO: 
	# 	Could be imroved by getting the email sent_time and use it as a filter in xmin_ago instead of the current 300 seconds
    
	recipient_emails = []
	emails_subjects = []
	account = Account(primary_smtp_address=sender_email, config=config,autodiscover=False, access_type=IMPERSONATION)
	tz = EWSTimeZone.localzone();
	right_now = tz.localize(EWSDateTime.now())
	xmin_ago = right_now - timedelta(minutes=300)
	for item in account.sent.filter(datetime_sent__gt=xmin_ago):
	#for item in account.sent.all().order_by('-datetime_received')[:10]:
		for attachment in item.attachments:
		 	if isinstance(attachment, FileAttachment):
		 		if attachment.name == file_name:
		 			emails_subjects.append(item.subject)					
#					logging.debug('Subject: '+item.subject+' '+attachment.name)
					if item.to_recipients is not None:
						for index, val in enumerate(item.to_recipients):
							if val.email_address not in recipient_emails: recipient_emails.append(val.email_address)
					if item.cc_recipients is not None:
						for index, val in enumerate(item.cc_recipients):
							if val.email_address not in recipient_emails: recipient_emails.append(val.email_address)
					if item.bcc_recipients is not None:
						for index, val in enumerate(item.bcc_recipients):
							if val.email_address not in recipient_emails: recipient_emails.append(val.email_address)
	logging.debug(emails_subjects)
	logging.debug(recipient_emails)						
	return emails_subjects,recipient_emails



def delete_malicious_email(recipient_email,attachment_name):
	# once the recipients are found we parse their mailboxes and delete the malicious email

	# Args:
	#     recipient_email (str)	: malware recipient email address
	#     attachment_name (str)	: the attachment file name to identify the malicious email

	# Returns:
	#     True is it parses the mailboxes, False if an error occurs

	# TODO:
	# 	ban the infected recipient machine with either IP or FortiClient using item.is_read

	account = Account(primary_smtp_address=recipient_email, config=config,autodiscover=False, access_type=IMPERSONATION)
	tz = EWSTimeZone.localzone();
	right_now = tz.localize(EWSDateTime.now())
	xmin_ago = right_now - timedelta(minutes=300)

	try:
		for item in account.inbox.filter(datetime_received__gt=xmin_ago):
			for attachment in item.attachments:
			 	if isinstance(attachment, FileAttachment):
			 		if attachment.name == attachment_name:
						# Either delete the infected email, or move it to trash
						#item.delete()
						item.move_to_trash()

						#send an alert to the recipient
						m = Message(
						    account=account,
							subject='FortiSIEM: You have received a Virus '+attachment_name,
							body='The maliicous email has been deleted from your inbox, please contact your administrator for further incident response',
							to_recipients=[Mailbox(email_address=recipient_email)],
						)
						m.send()
		return True
	except:
		return False



def main():
	data = {}
	# Collect event attributes from FSM supplied incident.xml (argv)
	data=xml_parser(sys.argv[1])
	source_ip = ''.join(data['source_ip'].splitlines())
	source_ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', source_ip )
	sender_username = ''.join(data['sender_username'].splitlines())
	sender_domain = ''.join(data['sender_domain'].splitlines())
	malicious_file_name = ''.join(data['malicious_file_name'].splitlines())
	# retrieves the user's principal email address which is required for Exchange Web Services
	# TODO: the base dn and domain can be retrieved from AD
	principal_email = check_principal_email('DOMAIN.com',ad_sys_user,ad_sys_password,'DC=DOMAIN,DC=com',sender_username)
	if principal_email is not None:
		email = principal_email
	else:
		print("couldn't get principal email")
		return(-1)

	logging.debug(source_ip[0]+' '+sender_username+' '+sender_domain+' '+malicious_file_name+' '+email)
	# retrieve the list of virus recipents from the sender sent folder
	email_subjects,recipient_emails = find_malicious_email(email,malicious_file_name)
	for index, val in enumerate(recipient_emails):
		logging.debug('Recipients Emails: '+val)
		delete_malicious_email(val,malicious_file_name)
	# optionaly we can disable the user account from AD 
	disable_ad_account('DOMAIN.com',ad_sys_user,ad_sys_password,'DC=DOMAIN,DC=com',sender_username)

#   TODO: ban_ip(fgt_ip,source_ip[0])   

if __name__ == "__main__":
	main()
