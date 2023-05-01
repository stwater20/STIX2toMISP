# sectoolstw RA MISP Object



## Useful Tools




### UUID Generator

https://www.uuidgenerator.net/version4

### JSON validator

https://jsonlint.com/


## Object Type

* AS: Autonomous system
* aba-rtn: ABA routing transit number
* anonymised: Anonymised value - described with the anonymisation object via a relationship
* attachment: Attachment with external information
* authentihash: Authenticode executable signature hash
* bank-account-nr: Bank account number without any routing number
* bic: Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code
* bin: Bank Identification Number
* boolean: Boolean value - to be used in objects
* bro: An NIDS rule in the Bro rule-format
* btc: Bitcoin Address
* campaign-id: Associated campaign ID
* campaign-name: Associated campaign name
* cc-number: Credit-Card Number
* cdhash: An Apple Code Directory Hash, identifying a code-signed Mach-O executable file
* chrome-extension-id: Chrome extension id
* comment: Comment or description in a human language
* community-id: a community ID flow hashing algorithm to map multiple traffic monitors into common flow id
* cookie: HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie.
* cortex: Cortex analysis result
* counter: An integer counter, generally to be used in objects
* country-of-residence: The country of residence of a natural person
* cpe: Common Platform Enumeration - structured naming scheme for information technology systems, software, and packages.
* dash: Dash Address
* date-of-birth: Date of birth of a natural person (in YYYY-MM-DD format)
* datetime: Datetime in the ISO 8601 format
* dkim: DKIM public key
* dkim-signature: DKIM signature
* dns-soa-email: RFC1035 mandates that DNS zones should have a SOA (Statement Of Authority) record that contains an email address where a PoC for the domain could be contacted. This can sometimes be used for attribution/linkage between different domains even if protected by whois privacy
* domain: A domain name used in the malware
* domain|ip: A domain name and its IP address (as found in DNS lookup) separated by a |
* email: An e-mail address
* email-attachment: File name of the email attachment.
* email-body: Email body
* email-dst: The destination email address. Used to describe the recipient when describing an e-mail.
* email-dst-display-name: Email destination display name
* email-header: Email header
* email-message-id: The email message ID
* email-mime-boundary: The email mime boundary separating parts in a multipart email
* email-reply-to: Email reply to header
* email-src: The source email address. Used to describe the sender when describing an e-mail.
* email-src-display-name: Email source display name
* email-subject: The subject of the email
* email-thread-index: The email thread index header
* email-x-mailer: Email x-mailer header
* eppn: eduPersonPrincipalName - eppn - the NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain.
* favicon-mmh3: favicon-mmh3 is the murmur3 hash of a favicon as used in Shodan.
* filename: Filename
* filename-pattern: A pattern in the name of a file
* filename|authentihash: A checksum in md5 format
* filename|impfuzzy: Import fuzzy hash - a fuzzy hash created based on the imports in the sample.
* filename|imphash: Import hash - a hash created based on the imports in the sample.
* filename|md5: A filename and an md5 hash separated by a |
* filename|pehash: A filename and a PEhash separated by a |
* filename|sha1: A filename and an sha1 hash separated by a |
* filename|sha224: A filename and a sha-224 hash separated by a |
* filename|sha256: A filename and an sha256 hash separated by a |
* filename|sha3-224: A filename and an sha3-224 hash separated by a |
* filename|sha3-256: A filename and an sha3-256 hash separated by a |
* filename|sha3-384: A filename and an sha3-384 hash separated by a |
* filename|sha3-512: A filename and an sha3-512 hash separated by a |
* filename|sha384: A filename and a sha-384 hash separated by a |
* filename|sha512: A filename and a sha-512 hash separated by a |
* filename|sha512/224: A filename and a sha-512/224 hash separated by a |
* filename|sha512/256: A filename and a sha-512/256 hash separated by a |
* filename|ssdeep: A checksum in ssdeep format
* filename|tlsh: A filename and a Trend Micro Locality Sensitive Hash separated by a |
* filename|vhash: A filename and a VirusTotal hash separated by a |
* first-name: First name of a natural person
* float: A floating point value.
* frequent-flyer-number: The frequent flyer number of a passenger
* full-name: Full name of a natural person
* gender: The gender of a natural person (Male, Female, Other, Prefer not to say)
* gene: GENE - Go Evtx sigNature Engine
* git-commit-id: A git commit ID.
* github-organisation: A github organisation
* github-repository: A github repository
* github-username: A github user name
* hassh-md5: hassh is a network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint.
* hasshserver-md5: hasshServer is a network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint.
* hex: A value in hexadecimal format
* hostname: A full host/dnsname of an attacker
* hostname|port: Hostname and port number separated by a |
* http-method: HTTP method used by the malware (e.g. POST, GET, ...).
* iban: International Bank Account Number
* identity-card-number: Identity card number
* impfuzzy: A fuzzy hash of import table of Portable Executable format
* imphash: Import hash - a hash created based on the imports in the sample.
* ip-dst: A destination IP address of the attacker or C&C server
* ip-dst|port: IP destination and port number separated by a |
* ip-src: A source IP address of the attacker
* ip-src|port: IP source and port number separated by a |
* issue-date-of-the-visa: The date on which the visa was issued
* ja3-fingerprint-md5: JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.
* jabber-id: Jabber ID
* jarm-fingerprint: JARM is a method for creating SSL/TLS server fingerprints.
* kusto-query: Kusto query - Kusto from Microsoft Azure is a service for storing and running interactive analytics over Big Data.
* last-name: Last name of a natural person
* link: Link to an external information
* mac-address: Mac address
* mac-eui-64: Mac EUI-64 address
* malware-sample: Attachment containing encrypted malware sample
* malware-type:
* md5: A checksum in md5 format
* middle-name: Middle name of a natural person
* mime-type: A media type (also MIME type and content type) is a two-part identifier for file formats and format contents transmitted on the Internet
* mobile-application-id: The application id of a mobile application
* mutex: Mutex, use the format \BaseNamedObjects\
* named pipe: Named pipe, use the format .\pipe\
* nationality: The nationality of a natural person
* other: Other attribute
* passenger-name-record-locator-number: The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers.
* passport-country: The country in which the passport was issued
* passport-expiration: The expiration date of a passport
* passport-number: The passport number of a natural person
* pattern-filename: A pattern in the name of a file
* pattern-in-file: Pattern in file that identifies the malware
* pattern-in-memory: Pattern in memory dump that identifies the malware
* pattern-in-traffic: Pattern in network traffic that identifies the malware
* payment-details: Payment details
* pdb: Microsoft Program database (PDB) path information
* pehash: PEhash - a hash calculated based of certain pieces of a PE executable file
* pgp-private-key: A PGP private key
* pgp-public-key: A PGP public key
* phone-number: Telephone Number
* place-of-birth: Place of birth of a natural person
* place-port-of-clearance: The port of clearance
* place-port-of-onward-foreign-destination: A Port where the passenger is transiting to
* place-port-of-original-embarkation: The original port of embarkation
* port: Port number
* primary-residence: The primary residence of a natural person
* process-state: State of a process
* prtn: Premium-Rate Telephone Number
* redress-number: The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems
* regkey: Registry key or value
* regkey|value: Registry value + data separated by |
* sha1: A checksum in sha1 format
* sha224: A checksum in sha-224 format
* sha256: A checksum in sha256 format
* sha3-224: A checksum in sha3-224 format
* sha3-256: A checksum in sha3-256 format
* sha3-384: A checksum in sha3-384 format
* sha3-512: A checksum in sha3-512 format
* sha384: A checksum in sha-384 format
* sha512: A checksum in sha-512 format
* sha512/224: A checksum in the sha-512/224 format
* sha512/256: A checksum in the sha-512/256 format
* sigma: Sigma - Generic Signature Format for SIEM Systems
* size-in-bytes: Size expressed in bytes
* snort: An IDS rule in Snort rule-format
* special-service-request: A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers.
* ssdeep: A checksum in ssdeep format
* ssh-fingerprint: A fingerprint of SSH key material
* stix2-pattern: STIX 2 pattern
* target-email: Attack Targets Email(s)
* target-external: External Target Organizations Affected by this Attack
* target-location: Attack Targets Physical Location(s)
* target-machine: Attack Targets Machine Name(s)
* target-org: Attack Targets Department or Organization(s)
* target-user: Attack Targets Username(s)
* telfhash: telfhash is symbol hash for ELF files, just like imphash is imports hash for PE files.
* text: Name, ID or a reference
* threat-actor: A string identifying the threat actor
* tlsh: A checksum in the Trend Micro Locality Sensitive Hash format
* travel-details: Travel details
* twitter-id: Twitter ID
* uri: Uniform Resource Identifier
* url: url
* user-agent: The user-agent used by the malware in the HTTP request.
* vhash: A VirusTotal checksum
* visa-number: Visa number
* vulnerability: A reference to the vulnerability used in the exploit
* weakness: A reference to the weakness used in the exploit
* whois-creation-date: The date of domain's creation, obtained from the WHOIS information.
* whois-registrant-email: The e-mail of a domain's registrant, obtained from the WHOIS information.
* whois-registrant-name: The name of a domain's registrant, obtained from the WHOIS information.
* whois-registrant-org: The org of a domain's registrant, obtained from the WHOIS information.
* whois-registrant-phone: The phone number of a domain's registrant, obtained from the WHOIS information.
* whois-registrar: The registrar of the domain, obtained from the WHOIS information.
* windows-scheduled-task: A scheduled task in windows
* windows-service-displayname: A windows service's displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service's name in applications.
* windows-service-name: A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname.
* x509-fingerprint-md5: X509 fingerprint in MD5 format
* x509-fingerprint-sha1: X509 fingerprint in SHA-1 format
* x509-fingerprint-sha256: X509 fingerprint in SHA-256 format
* xmr: Monero Address
* yara: Yara signature
* zeek: An NIDS rule in the Zeek rule-format


## Reference

https://www.circl.lu/doc/misp/categories-and-types/#types
