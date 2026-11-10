/**
 * CyberGuard AI — Windows Event Knowledge Base Lookup
 * ============================================================================
 * Generated from the 10 Windows event definition catalogs in the knowledge base.
 * Provides non-technical, human-friendly presentation for ordinary people.
 */

export interface EventKnowledgeItem {
  id: string;
  title: string;
  category: string;
  plainEnglish: string;
}

export const WINDOWS_EVENT_KNOWLEDGE: Record<string, EventKnowledgeItem> = {
  "4720": {
    "id": "4720",
    "title": "A new user account was created",
    "category": "Account Management",
    "plainEnglish": "A new login account was created on this computer. This is normal during onboarding, but if nobody expected it an intruder may be setting up a way to log in."
  },
  "4722": {
    "id": "4722",
    "title": "A user account was enabled",
    "category": "Account Management",
    "plainEnglish": "A disabled login was turned back on. If you didn't ask for this, someone may be trying to reuse an old or suspended account."
  },
  "4723": {
    "id": "4723",
    "title": "Someone tried to change an account password",
    "category": "Account Management",
    "plainEnglish": "Someone tried to change a password. Because changing requires knowing the current password, this is usually the user themselves."
  },
  "4724": {
    "id": "4724",
    "title": "An administrator reset a user's password",
    "category": "Account Management",
    "plainEnglish": "An administrator reset a user's password. This is normal when a user forgets it, but if the user didn't ask, someone may have reset it to take over the account."
  },
  "4725": {
    "id": "4725",
    "title": "A user account was disabled",
    "category": "Account Management",
    "plainEnglish": "A user account was disabled \u2014 the user can no longer sign in until re-enabled."
  },
  "4726": {
    "id": "4726",
    "title": "A user account was deleted",
    "category": "Account Management",
    "plainEnglish": "A user account was deleted. This is destructive \u2014 the account and its access are gone. Verify this was authorized."
  },
  "4727": {
    "id": "4727",
    "title": "A global security group was created",
    "category": "Account Management",
    "plainEnglish": "A new global security group was created. Global groups are used to grant access across the domain."
  },
  "4728": {
    "id": "4728",
    "title": "Someone was added to a global security group",
    "category": "Account Management",
    "plainEnglish": "Someone was added to a global security group. This is how Windows grants permissions \u2014 if the group is sensitive (Domain Admins, Enterprise Admins), the member now has significant access."
  },
  "4729": {
    "id": "4729",
    "title": "Someone was removed from a global security group",
    "category": "Account Management",
    "plainEnglish": "Someone was removed from a global security group. This revokes access."
  },
  "4732": {
    "id": "4732",
    "title": "Someone was added to a local security group",
    "category": "Account Management",
    "plainEnglish": "Someone was added to a local security group on this computer. If the group is Administrators, the member now has full control over this machine."
  },
  "4733": {
    "id": "4733",
    "title": "Someone was removed from a local security group",
    "category": "Account Management",
    "plainEnglish": "Someone was removed from a local security group on this computer. This revokes local access."
  },
  "4735": {
    "id": "4735",
    "title": "A local security group was changed",
    "category": "Account Management",
    "plainEnglish": "A local security group's properties were changed. This usually means a name or description, not membership."
  },
  "4737": {
    "id": "4737",
    "title": "A global security group was changed",
    "category": "Account Management",
    "plainEnglish": "A global security group's properties were changed."
  },
  "4738": {
    "id": "4738",
    "title": "A user account was changed",
    "category": "Account Management",
    "plainEnglish": "A user account's properties were modified \u2014 this could be a name change, description update, or other attribute. If unexpected, review what changed."
  },
  "4739": {
    "id": "4739",
    "title": "The domain password or lockout policy was changed",
    "category": "Account Management",
    "plainEnglish": "The domain's password or lockout policy was changed. This affects every user in the domain. If unexpected, treat it as high priority \u2014 a weaker policy undermines every account."
  },
  "4742": {
    "id": "4742",
    "title": "A computer account was changed",
    "category": "Account Management",
    "plainEnglish": "A computer's domain account was changed. This can be routine (renaming a machine) or malicious (hijacking a computer's domain identity)."
  },
  "4744": {
    "id": "4744",
    "title": "A distribution (non-security) local group was created",
    "category": "Account Management",
    "plainEnglish": "A distribution group (used for email lists, not access control) was created locally."
  },
  "4745": {
    "id": "4745",
    "title": "A distribution (non-security) local group was changed",
    "category": "Account Management",
    "plainEnglish": "A distribution (non-security) local group's properties were changed."
  },
  "4746": {
    "id": "4746",
    "title": "Someone was added to a distribution local group",
    "category": "Account Management",
    "plainEnglish": "Someone was added to a distribution (non-security) local group. This only affects email membership, not access."
  },
  "4750": {
    "id": "4750",
    "title": "A distribution (non-security) global group was changed",
    "category": "Account Management",
    "plainEnglish": "A distribution (non-security) global group's properties were changed."
  },
  "4751": {
    "id": "4751",
    "title": "Someone was added to a distribution global group",
    "category": "Account Management",
    "plainEnglish": "Someone was added to a distribution (non-security) global group."
  },
  "4752": {
    "id": "4752",
    "title": "Someone was removed from a distribution global group",
    "category": "Account Management",
    "plainEnglish": "Someone was removed from a distribution (non-security) global group."
  },
  "4754": {
    "id": "4754",
    "title": "A universal security group was created",
    "category": "Account Management",
    "plainEnglish": "A new universal security group was created. Universal groups grant access across multiple domains."
  },
  "4755": {
    "id": "4755",
    "title": "A universal security group was changed",
    "category": "Account Management",
    "plainEnglish": "A universal security group's properties were changed."
  },
  "4756": {
    "id": "4756",
    "title": "Someone was added to a universal security group",
    "category": "Account Management",
    "plainEnglish": "Someone was added to a universal security group \u2014 this grants cross-domain access."
  },
  "4757": {
    "id": "4757",
    "title": "Someone was removed from a universal security group",
    "category": "Account Management",
    "plainEnglish": "Someone was removed from a universal security group."
  },
  "4760": {
    "id": "4760",
    "title": "A distribution universal group was changed",
    "category": "Account Management",
    "plainEnglish": "A distribution (non-security) universal group's properties were changed."
  },
  "4761": {
    "id": "4761",
    "title": "Someone was added to a distribution universal group",
    "category": "Account Management",
    "plainEnglish": "Someone was added to a distribution (non-security) universal group."
  },
  "4762": {
    "id": "4762",
    "title": "Someone was removed from a distribution universal group",
    "category": "Account Management",
    "plainEnglish": "Someone was removed from a distribution (non-security) universal group."
  },
  "4764": {
    "id": "4764",
    "title": "A group's type was changed",
    "category": "Account Management",
    "plainEnglish": "A group's type was changed \u2014 for example, from distribution to security. This can change whether the group grants access."
  },
  "4767": {
    "id": "4767",
    "title": "A locked user account was unlocked",
    "category": "Account Management",
    "plainEnglish": "A locked-out user account was unlocked by an administrator. The user can now sign in again."
  },
  "4793": {
    "id": "4793",
    "title": "The password policy checking API was called",
    "category": "Account Management",
    "plainEnglish": "An application checked a proposed password against the domain's password policy. Routine for apps that let users change or set passwords."
  },
  "4794": {
    "id": "4794",
    "title": "The DSRM administrator password was set",
    "category": "Account Management",
    "plainEnglish": "The Directory Services Restore Mode (DSRM) administrator password was changed. DSRM is an offline admin mode on domain controllers \u2014 this is a rare, high-impact operation."
  },
  "4797": {
    "id": "4797",
    "title": "An attempt was made to query blank passwords",
    "category": "Account Management",
    "plainEnglish": "An attempt was made to find accounts with blank passwords. Attackers do this to find accounts with no password protection."
  },
  "4798": {
    "id": "4798",
    "title": "A user's local group membership was enumerated",
    "category": "Account Management",
    "plainEnglish": "Someone listed the local groups a specific user belongs to. This is a common admin action and also a common attacker reconnaissance step."
  },
  "4799": {
    "id": "4799",
    "title": "A local group's membership was enumerated",
    "category": "Account Management",
    "plainEnglish": "Someone listed the members of a local security group. Same idea as the previous event but listing a group's members."
  },
  "4610": {
    "id": "4610",
    "title": "An authentication component was loaded",
    "category": "Authentication",
    "plainEnglish": "Windows loaded a component that handles logins. This is normal at startup. If an unfamiliar component loads after a change, investigate."
  },
  "4611": {
    "id": "4611",
    "title": "A sign-in component registered with Windows",
    "category": "Authentication",
    "plainEnglish": "A login-process component registered with Windows. Normal for known Windows components; unfamiliar names are worth review."
  },
  "4622": {
    "id": "4622",
    "title": "A Windows security package was loaded",
    "category": "Authentication",
    "plainEnglish": "Windows loaded a security package used for authentication. Normal for known packages."
  },
  "4624": {
    "id": "4624",
    "title": "A sign-in succeeded",
    "category": "Authentication",
    "plainEnglish": "Someone successfully signed in. The fields tell you who, from where, and how (local keyboard, Remote Desktop, network share, service). A successful sign-in is normal \u2014 what matters is whether it was expected."
  },
  "4625": {
    "id": "4625",
    "title": "A sign-in attempt failed",
    "category": "Authentication",
    "plainEnglish": "Someone tried to sign in but Windows rejected it \u2014 usually a wrong password. One failure is common (typo, saved password on another device). Many failures in a row may mean someone is guessing passwords."
  },
  "4634": {
    "id": "4634",
    "title": "A sign-in session ended",
    "category": "Authentication",
    "plainEnglish": "A logon session ended. Sessions correspond to successful logons; matching the Logon ID with a 4624 shows how long the session lasted."
  },
  "4647": {
    "id": "4647",
    "title": "A user started signing out",
    "category": "Authentication",
    "plainEnglish": "The user clicked sign out (as opposed to the machine shutting down or the session ending for another reason)."
  },
  "4648": {
    "id": "4648",
    "title": "A program signed in using specified credentials",
    "category": "Authentication",
    "plainEnglish": "A program logged in using a different account than the current user \u2014 for example, 'Run as different user' or a scheduled task running as a service account."
  },
  "4649": {
    "id": "4649",
    "title": "A possible authentication replay was detected",
    "category": "Authentication",
    "plainEnglish": "Windows detected what looks like a replay attack \u2014 authentication information was reused in a way that suggests interception. Take this seriously if corroborated."
  },
  "4740": {
    "id": "4740",
    "title": "A user account was locked",
    "category": "Authentication",
    "plainEnglish": "A user account was locked because of too many wrong password attempts. Often caused by a forgotten password or an outdated saved password on another device. Repeated lockouts can indicate password guessing."
  },
  "4768": {
    "id": "4768",
    "title": "A Kerberos sign-in ticket was requested",
    "category": "Authentication",
    "plainEnglish": "A user asked the domain controller for a Kerberos sign-in ticket. This is the first step of a domain login and normal for domain users. Unusual failure patterns or unusual sources are worth review."
  },
  "4769": {
    "id": "4769",
    "title": "Access to a domain service was requested",
    "category": "Authentication",
    "plainEnglish": "A user asked for a ticket to access a specific domain service (file share, database, etc.). Shows which accounts access which services."
  },
  "4770": {
    "id": "4770",
    "title": "A Kerberos service ticket was renewed",
    "category": "Authentication",
    "plainEnglish": "A Kerberos ticket was renewed to extend a session. Routine in most environments."
  },
  "4771": {
    "id": "4771",
    "title": "A Kerberos sign-in check failed",
    "category": "Authentication",
    "plainEnglish": "A Kerberos login attempt failed the pre-authentication check \u2014 usually a wrong password. Repeated failures can indicate password guessing."
  },
  "4772": {
    "id": "4772",
    "title": "A Kerberos ticket request failed",
    "category": "Authentication",
    "plainEnglish": "A Kerberos ticket request failed. The event's result code tells you why \u2014 read it before drawing conclusions."
  },
  "4774": {
    "id": "4774",
    "title": "An account was mapped for sign-in",
    "category": "Authentication",
    "plainEnglish": "An account was mapped to a logon \u2014 used in authentication flows that map an external identity to a Windows account."
  },
  "4775": {
    "id": "4775",
    "title": "Windows could not map an account for sign-in",
    "category": "Authentication",
    "plainEnglish": "An authentication mapping attempt failed. Usually a configuration or account problem; recurring unexplained failures deserve review."
  },
  "4776": {
    "id": "4776",
    "title": "Windows checked NTLM sign-in credentials",
    "category": "Authentication",
    "plainEnglish": "Windows checked a username and password using NTLM, a legacy authentication protocol. Succeeds silently for older apps. Failures are usually more interesting than successes."
  },
  "4777": {
    "id": "4777",
    "title": "NTLM sign-in credentials could not be validated",
    "category": "Authentication",
    "plainEnglish": "NTLM credential validation failed \u2014 usually a wrong password, outdated cached credentials, or a password-guessing attempt."
  },
  "4657": {
    "id": "4657",
    "title": "A registry value was modified",
    "category": "File, Object and Registry Access",
    "plainEnglish": "A registry setting was changed. Registry entries control many Windows behaviours \u2014 attackers use them for persistence and to disable security features."
  },
  "4661": {
    "id": "4661",
    "title": "A handle to an object was requested",
    "category": "File, Object and Registry Access",
    "plainEnglish": "A program asked for access to a securable object (file, registry key, service, etc.). Shows what access was requested and whether it was granted."
  },
  "4662": {
    "id": "4662",
    "title": "An operation was performed on an object",
    "category": "File, Object and Registry Access",
    "plainEnglish": "An operation was performed on a directory service (AD) object. Useful for tracking changes to users, groups, computers, and GPOs."
  },
  "4663": {
    "id": "4663",
    "title": "An attempt was made to access an object",
    "category": "File, Object and Registry Access",
    "plainEnglish": "A program tried to access a specific file, folder, or registry key. Whether the access succeeded is recorded in the event."
  },
  "4665": {
    "id": "4665",
    "title": "An application client context was created",
    "category": "File, Object and Registry Access",
    "plainEnglish": "An application created a client authentication context. Used by applications doing custom authentication."
  },
  "4666": {
    "id": "4666",
    "title": "An application attempted an operation",
    "category": "File, Object and Registry Access",
    "plainEnglish": "An application performed a security-sensitive operation. Which operation depends on the event fields."
  },
  "4667": {
    "id": "4667",
    "title": "An application client context was deleted",
    "category": "File, Object and Registry Access",
    "plainEnglish": "An application cleaned up its client authentication context."
  },
  "4670": {
    "id": "4670",
    "title": "Permissions on an object were changed",
    "category": "File, Object and Registry Access",
    "plainEnglish": "Someone changed the permissions on a file, folder, or object. This can grant new access \u2014 review what was changed and for whom."
  },
  "4946": {
    "id": "4946",
    "title": "A rule was added to the firewall exception list",
    "category": "Firewall",
    "plainEnglish": "A new firewall exception was added \u2014 a new hole was opened. If you didn't request this, someone may be opening access for an attacker."
  },
  "4948": {
    "id": "4948",
    "title": "A firewall exception was deleted",
    "category": "Firewall",
    "plainEnglish": "A firewall exception was removed. This can be routine cleanup or an attempt to break expected access."
  },
  "4956": {
    "id": "4956",
    "title": "The active firewall profile changed",
    "category": "Firewall",
    "plainEnglish": "Windows Firewall switched which profile is active (Domain, Private, Public). Different profiles have different rules, so switching can change exposure."
  },
  "5024": {
    "id": "5024",
    "title": "The Windows Firewall service started",
    "category": "Firewall",
    "plainEnglish": "The Windows Firewall service started. This is normal at boot \u2014 but if the firewall had been stopped, this event can indicate it was restarted after tampering."
  },
  "5033": {
    "id": "5033",
    "title": "The Windows Firewall driver started",
    "category": "Firewall",
    "plainEnglish": "The firewall's kernel driver started. Normal at boot."
  },
  "5059": {
    "id": "5059",
    "title": "A key-file operation occurred",
    "category": "Firewall",
    "plainEnglish": "The firewall performed an operation on a key file (used to securely store configuration). Routine during firewall configuration changes."
  },
  "4825": {
    "id": "4825",
    "title": "A user was denied access to Remote Desktop",
    "category": "Network Activity",
    "plainEnglish": "Someone was denied access to Remote Desktop. Repeated denials can indicate someone trying to guess RDP credentials."
  },
  "4886": {
    "id": "4886",
    "title": "Certificate Services received a certificate request",
    "category": "Network Activity",
    "plainEnglish": "The certificate authority received a request for a new certificate."
  },
  "4887": {
    "id": "4887",
    "title": "Certificate Services approved and issued a certificate",
    "category": "Network Activity",
    "plainEnglish": "The certificate authority approved a certificate request and issued a certificate."
  },
  "4888": {
    "id": "4888",
    "title": "Certificate Services denied a certificate request",
    "category": "Network Activity",
    "plainEnglish": "The certificate authority denied a certificate request."
  },
  "4893": {
    "id": "4893",
    "title": "Certificate Services archived a key",
    "category": "Network Activity",
    "plainEnglish": "The certificate authority archived a private key. This is a sensitive operation because archived keys can be recovered."
  },
  "4898": {
    "id": "4898",
    "title": "Certificate Services loaded a template",
    "category": "Network Activity",
    "plainEnglish": "The certificate authority loaded a certificate template."
  },
  "5136": {
    "id": "5136",
    "title": "A directory service object was modified",
    "category": "Network Activity",
    "plainEnglish": "An Active Directory object was modified. AD is the directory that stores users, computers, and permissions \u2014 changes to objects can grant access."
  },
  "5137": {
    "id": "5137",
    "title": "A directory service object was created",
    "category": "Network Activity",
    "plainEnglish": "A new object (user, computer, group, OU) was created in Active Directory."
  },
  "5140": {
    "id": "5140",
    "title": "A network share was accessed",
    "category": "Network Activity",
    "plainEnglish": "Someone accessed a shared folder or file share over the network."
  },
  "5145": {
    "id": "5145",
    "title": "A network share access check occurred",
    "category": "Network Activity",
    "plainEnglish": "Windows checked whether a user has permission to access a specific file or folder on a share. Shows which files were accessed."
  },
  "5632": {
    "id": "5632",
    "title": "A wireless network authentication was requested",
    "category": "Network Activity",
    "plainEnglish": "A request was made to authenticate to a wireless network."
  },
  "5633": {
    "id": "5633",
    "title": "A wired network authentication was requested",
    "category": "Network Activity",
    "plainEnglish": "A request was made to authenticate to a wired network."
  },
  "6272": {
    "id": "6272",
    "title": "Network Policy Server granted access to a user",
    "category": "Network Activity",
    "plainEnglish": "A Network Policy Server (used for RADIUS, VPN, and 802.1X) granted access to a user."
  },
  "6273": {
    "id": "6273",
    "title": "Network Policy Server denied access to a user",
    "category": "Network Activity",
    "plainEnglish": "A Network Policy Server denied access. Repeated denials can indicate guessing or misconfiguration."
  },
  "6278": {
    "id": "6278",
    "title": "Network Policy Server granted full access to a user",
    "category": "Network Activity",
    "plainEnglish": "NPS granted full access (as opposed to limited access). Full access may include more permissive network access."
  },
  "6416": {
    "id": "6416",
    "title": "A new external device was recognized",
    "category": "Network Activity",
    "plainEnglish": "A new external device (USB, Bluetooth, etc.) was connected and recognised. Useful for detecting unauthorised USB drives or peripherals."
  },
  "6423": {
    "id": "6423",
    "title": "A device install was blocked by policy",
    "category": "Network Activity",
    "plainEnglish": "A device installation was blocked by policy. This can be routine (device-control policy) or a sign someone tried to install an unauthorized device."
  },
  "6424": {
    "id": "6424",
    "title": "A previously blocked device install was allowed",
    "category": "Network Activity",
    "plainEnglish": "A device that had been blocked was allowed to install after policy was changed. If policy change wasn't authorized, this is a red flag."
  },
  "8001": {
    "id": "8001",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8002": {
    "id": "8002",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8003": {
    "id": "8003",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8004": {
    "id": "8004",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8005": {
    "id": "8005",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8006": {
    "id": "8006",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8007": {
    "id": "8007",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "8222": {
    "id": "8222",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "26401": {
    "id": "26401",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "30004": {
    "id": "30004",
    "title": "This event is not yet explained",
    "category": "Network Activity",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "4618": {
    "id": "4618",
    "title": "A monitored security event pattern occurred",
    "category": "Other Windows Events",
    "plainEnglish": "Windows detected a pattern of security events that you configured for monitoring \u2014 for example, several failed logons followed by a successful one. Think of it as an alarm the system raised for you."
  },
  "4870": {
    "id": "4870",
    "title": "This event is not yet explained",
    "category": "Other Windows Events",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "4897": {
    "id": "4897",
    "title": "This event is not yet explained",
    "category": "Other Windows Events",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "4931": {
    "id": "4931",
    "title": "A directory service replica was modified",
    "category": "Other Windows Events",
    "plainEnglish": "A copy of the Active Directory database on another domain controller was modified. Routine replication, or part of an AD-level change."
  },
  "4932": {
    "id": "4932",
    "title": "Directory service replica synchronization began",
    "category": "Other Windows Events",
    "plainEnglish": "A domain controller started synchronizing its copy of Active Directory with another domain controller."
  },
  "4933": {
    "id": "4933",
    "title": "Directory service replica synchronization ended",
    "category": "Other Windows Events",
    "plainEnglish": "A domain controller finished synchronizing its copy of Active Directory."
  },
  "4985": {
    "id": "4985",
    "title": "This event is not yet explained",
    "category": "Other Windows Events",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "5124": {
    "id": "5124",
    "title": "This event is not yet explained",
    "category": "Other Windows Events",
    "plainEnglish": "We do not currently have a plain-English explanation for this event. Please ask IT or your security team."
  },
  "4672": {
    "id": "4672",
    "title": "A new sign-in was granted administrator-level privileges",
    "category": "Privilege and Group Management",
    "plainEnglish": "A sign-in was granted powerful administrator privileges. If you see this for an account you didn't expect \u2014 especially a non-admin account \u2014 an intruder may have escalated privileges."
  },
  "4673": {
    "id": "4673",
    "title": "A privileged service was called",
    "category": "Privilege and Group Management",
    "plainEnglish": "A program used a privileged Windows service (which requires administrator rights). Attackers use these services for actions like tampering with security or disabling protections."
  },
  "4674": {
    "id": "4674",
    "title": "An operation was attempted on a privileged object",
    "category": "Privilege and Group Management",
    "plainEnglish": "A program tried to perform an operation that needs administrator-level privilege on a protected object."
  },
  "4675": {
    "id": "4675",
    "title": "SIDs were filtered",
    "category": "Privilege and Group Management",
    "plainEnglish": "Windows removed one or more security identifiers (SIDs) from a sign-in token \u2014 usually to enforce access restrictions or contain a potentially risky session."
  },
  "4704": {
    "id": "4704",
    "title": "A user right was assigned to an account",
    "category": "Privilege and Group Management",
    "plainEnglish": "A specific Windows privilege (like 'Log on as a service' or 'Debug programs') was granted to an account. These rights can be powerful \u2014 an unexpected grant is serious."
  },
  "4705": {
    "id": "4705",
    "title": "A user right was removed from an account",
    "category": "Privilege and Group Management",
    "plainEnglish": "A Windows privilege was removed from an account \u2014 access was reduced."
  },
  "4716": {
    "id": "4716",
    "title": "Trusted domain information was modified",
    "category": "Privilege and Group Management",
    "plainEnglish": "Configuration of a domain trust was modified. Trusts let two domains share authentication \u2014 changes can have big security impact."
  },
  "4717": {
    "id": "4717",
    "title": "System security access was granted to an account",
    "category": "Privilege and Group Management",
    "plainEnglish": "An account was granted the ability to perform sensitive system-level actions \u2014 for example, taking ownership of files or shutting down the system."
  },
  "4718": {
    "id": "4718",
    "title": "System security access was removed from an account",
    "category": "Privilege and Group Management",
    "plainEnglish": "An account lost a sensitive system-level access right."
  },
  "4765": {
    "id": "4765",
    "title": "SID History was added to an account",
    "category": "Privilege and Group Management",
    "plainEnglish": "SID History lets an account inherit permissions from another account. Attackers add SID History to grant themselves extra access \u2014 this is a serious event."
  },
  "4766": {
    "id": "4766",
    "title": "An attempt to add SID History failed",
    "category": "Privilege and Group Management",
    "plainEnglish": "Someone tried to add SID History to an account and the attempt failed. Even though it failed, the attempt itself is suspicious."
  },
  "4964": {
    "id": "4964",
    "title": "Special groups were assigned to a new logon",
    "category": "Privilege and Group Management",
    "plainEnglish": "A sign-in was granted membership in special Windows groups (like Administrators or a custom sensitive group) beyond what the account normally has."
  },
  "4688": {
    "id": "4688",
    "title": "A new process was started",
    "category": "Process and Application Activity",
    "plainEnglish": "A program was started. If you don't recognize the program, or if it was launched by a suspicious parent (like Office launching PowerShell), investigate."
  },
  "4689": {
    "id": "4689",
    "title": "A process stopped",
    "category": "Process and Application Activity",
    "plainEnglish": "A program stopped running. Usually routine \u2014 correlate with 4688 to know how long it ran and how it exited."
  },
  "4697": {
    "id": "4697",
    "title": "A service was installed",
    "category": "Process and Application Activity",
    "plainEnglish": "A new Windows service (a background program) was installed. Attackers use services to run malicious code persistently. If you didn't install a new service, investigate."
  },
  "1102": {
    "id": "1102",
    "title": "The Security audit log was cleared",
    "category": "Security Policy",
    "plainEnglish": "Someone cleared the Windows Security audit log. This erases the record of activity on this computer. Attackers do this to cover their tracks \u2014 treat it as an emergency unless you specifically requested it."
  },
  "4719": {
    "id": "4719",
    "title": "The system audit policy was changed",
    "category": "Security Policy",
    "plainEnglish": "The rules that decide which Windows events get recorded were changed. If audit is turned off for important events, attackers can act without leaving a trace."
  },
  "4902": {
    "id": "4902",
    "title": "The per-user audit policy table was created",
    "category": "Security Policy",
    "plainEnglish": "Windows built a table of per-user auditing rules. This is usually routine (happens at policy refresh) but can indicate audit policy changes."
  },
  "4904": {
    "id": "4904",
    "title": "An attempt was made to register a security event source",
    "category": "Security Policy",
    "plainEnglish": "A program tried to register itself as a source of security events. Legitimate programs register at install; unexpected registrations can indicate tampering."
  },
  "4905": {
    "id": "4905",
    "title": "An attempt was made to unregister a security event source",
    "category": "Security Policy",
    "plainEnglish": "A program tried to unregister itself as a source of security events. This can be routine during software removal, or an attempt to stop logging from a program."
  },
  "4907": {
    "id": "4907",
    "title": "Auditing settings on an object were changed",
    "category": "Security Policy",
    "plainEnglish": "The auditing settings for a specific file, folder, registry key, or other object were changed. This affects whether activity on that object gets recorded \u2014 turning audit off is a defence-evasion technique."
  },
  "1100": {
    "id": "1100",
    "title": "The event log service shut down",
    "category": "System Activity",
    "plainEnglish": "The Windows event log service stopped. This usually happens during a normal shutdown. If it happens during normal operation, the log is no longer being written \u2014 a sign of tampering or a serious problem."
  },
  "1107": {
    "id": "1107",
    "title": "The event log service encountered an error",
    "category": "System Activity",
    "plainEnglish": "The Windows event log service hit an error. Some events may be missing as a result."
  },
  "1108": {
    "id": "1108",
    "title": "The event log service had an error processing a message",
    "category": "System Activity",
    "plainEnglish": "The Windows event log service had an error while processing a specific event \u2014 that event may not have been recorded correctly."
  },
  "4608": {
    "id": "4608",
    "title": "Windows started",
    "category": "System Activity",
    "plainEnglish": "The Windows security subsystem started. Marks the beginning of a Windows session \u2014 useful for establishing a timeline."
  },
  "4614": {
    "id": "4614",
    "title": "A notification package was loaded",
    "category": "System Activity",
    "plainEnglish": "Windows loaded a notification package (used for alerts or monitoring). Usually routine during startup."
  },
  "6144": {
    "id": "6144",
    "title": "Security policy from Group Policy was applied successfully",
    "category": "System Activity",
    "plainEnglish": "Group Policy successfully applied a security policy to this computer. Routine and reassuring \u2014 the expected configuration is in place."
  },
  "6145": {
    "id": "6145",
    "title": "Security policy processing had errors",
    "category": "System Activity",
    "plainEnglish": "Group Policy had errors applying security policy to this computer. Some expected security settings may not be in effect \u2014 investigate."
  },
  "7045": {
    "id": "7045",
    "title": "A new Windows service was installed",
    "category": "System Activity",
    "plainEnglish": "A new background service was registered on this computer."
  }
};

export function extractEventId(eventType?: string | null, rawPayload?: Record<string, any> | null): string | null {
  if (rawPayload) {
    const rawId = rawPayload.EventID ?? rawPayload.event_id ?? rawPayload.eventId;
    if (rawId !== undefined && rawId !== null) return String(rawId).trim();
  }
  if (!eventType) return null;
  const match = String(eventType).match(/(?:windows(?:\.[a-z]+)?\.)(\d{3,5})/i);
  if (match && match[1]) return match[1];
  const numMatch = String(eventType).match(/\b(\d{4,5})\b/);
  return (numMatch && numMatch[1]) ? numMatch[1] : null;
}

export function cleanProcessName(rawProcess?: string | null): string {
  if (!rawProcess) return "System Process";
  const trimmed = String(rawProcess).trim();
  if (!trimmed || trimmed === "None" || trimmed === "-") return "System Process";
  const normalized = trimmed.replace(/\\/g, "/");
  const base = normalized.split("/").pop() || trimmed;
  return base;
}

export function getEventDisplayInfo(evt: {
  event_type?: string;
  category?: string;
  title?: string;
  details?: string;
  event_id?: string;
  category_label?: string;
  process_display?: string;
  process_name?: string;
  username?: string;
  hostname?: string;
  raw_payload?: Record<string, any>;
}) {
  const eventId = evt.event_id || extractEventId(evt.event_type, evt.raw_payload);
  const kbItem = eventId ? WINDOWS_EVENT_KNOWLEDGE[eventId] : null;

  // Title: prioritize backend title -> KB title -> fallback
  let title = evt.title;
  if (!title || title === evt.event_type || title.startsWith("windows.")) {
    if (kbItem) {
      title = kbItem.title;
    } else if (eventId === "4688") {
      title = "A new process was started";
    } else if (eventId === "4624") {
      title = "Successful Account Logon";
    } else if (eventId === "4625") {
      title = "Account Failed to Log On";
    } else if (eventId === "7045") {
      title = "A new Windows service was installed";
    } else if (eventId) {
      title = `Windows Security Event ${eventId}`;
    } else {
      title = "Operating System Activity";
    }
  }

  // Category
  let category = evt.category_label;
  if (!category || category.toLowerCase() === "other" || category.toLowerCase() === "general" || category.toLowerCase() === "endpoint") {
    if (kbItem) {
      category = kbItem.category;
    } else if (eventId === "4688" || eventId === "4689") {
      category = "Process & Application Activity";
    } else if (eventId === "4624" || eventId === "4625" || eventId === "4634") {
      category = "Account Sign-In & Auth";
    } else if (eventId === "7045" || eventId === "7036") {
      category = "System & Service Activity";
    } else {
      category = "System Activity";
    }
  }

  // Clean process
  const processDisplay = evt.process_display || cleanProcessName(evt.process_name || evt.raw_payload?.NewProcessName || evt.raw_payload?.ProcessName);

  // Friendly details sentence
  const host = evt.hostname || "Windows PC";
  const user = (evt.username && evt.username.toLowerCase() !== "system" && evt.username.toLowerCase() !== "unknown") ? evt.username : null;
  const userSuffix = user ? ` by ${user}` : "";

  let friendlyDetails = evt.details;
  if (!friendlyDetails || friendlyDetails.startsWith("windows.security") || friendlyDetails.includes("windows.security.")) {
    if (eventId === "4688") {
      friendlyDetails = `A program (${processDisplay}) was launched on ${host}${userSuffix}.`;
    } else if (eventId === "4624") {
      friendlyDetails = `Successful sign-in to account on ${host}${userSuffix}.`;
    } else if (eventId === "4625") {
      friendlyDetails = `Sign-in attempt failed on ${host}${userSuffix}.`;
    } else if (eventId === "7045") {
      friendlyDetails = `A background service was registered on ${host}.`;
    } else if (kbItem) {
      friendlyDetails = `${kbItem.title} recorded on ${host}${userSuffix}.`;
    } else {
      friendlyDetails = `System activity recorded on ${host}.`;
    }
  }

  const plainEnglish = kbItem?.plainEnglish || (
    eventId === "4688" ? "A program was started. If you do not recognize the program, investigate." :
    eventId === "4624" ? "A user successfully logged on to this computer." :
    eventId === "4625" ? "A sign-in attempt failed, usually due to a mistyped password." :
    "Operating system operational activity logged during regular computer usage."
  );

  return {
    eventId,
    title,
    category,
    processDisplay,
    friendlyDetails,
    plainEnglish,
    badgeLabel: eventId ? `Event ${eventId}` : (evt.event_type || "Event"),
    deviceDisplay: host,
    userDisplay: user || "System Account",
  };
}
