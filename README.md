# Zeroday_post_delivery_remediation
a post delivery remediate a zero day malware attack


A demo scenario revolving around FortiSIEM remediating an attack in which a malicious email with zero day malware was sent from within the organization using stolen credentials.

An attacker uses stolen credentials and uses Outlook Web Access to send a 0day malware as an attachment to a target recipient
FortiWeb which is publishing and inspecting OWA/ActiveSync extracts the attachment and forward a copy of it to FortiSandbox and send a syslog to FortiSIEM
FortiSandbox detects the 0day malware and sends a syslog to FortiSIEM
a couple of minutes later FortiWeb downloads the new malware package from FortiSandbox which has the 0day malware signature, a syslog is sent to FortiSIEM with its details.
FortiSIEM using a slightly modified FortiWeb parser (Attached) collects the logs from (2. And 4.) and uses the attachment ID, and source port within a correlation rule (Attached) to trigger a remediation python script (attached)
The script then:
Connects to Active Directory DC and disables the stolen account
Opens the sender’s mailbox on MS Exchange and retrieves the recipients addresses
Opens each recipient mailbox and delete the malicious email
Sends a notification to each recipient with the incident details
The script includes many explanatory comments and needs to be customized according to the environment (domain name, user, pass, base dn …etc)

What is missing is ActiveSync parsing (in case of Outlook instead of OWA) and the integration with FortiGate and FortiClient (Blacklist), if anyone is interested to cooperate on the scenario let me know.

