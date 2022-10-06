# Web Application Penetration Testing
_Web App Penetration Strategies._


## Contents
* [Code injection](#code-injection)
* [Scanning](#scanning)
* [Brute Force Attacks](#brute-force-attacks)
* [Extracting Data from db](#extracting-data-from-db)
* [Change the code of the webpage](#change-the-code-of-the-webpage)
* [Upload malicious files](#upload-malicious-files)
* [Exploit user inputs](#exploit-user-inputs)
* [Exploit poorly written code](#exploit-poorly-written-code)
* [Xss attack, js code injection](#xss-attack-js-code-injection)


### Code injection
Using code to execute sql queries or cli commands.


### Poorly written code
- Most of the root of attacks is because of a poorly written code.
- JS, HTML, CSS - all of them can be used to attack websites with code injection.
- JS - XSS attack is the most dangerous. JS can execute functions, so it has the most power to attack.


### Brute Force Attacks
- Send multiple passwords until it guess the right one. Weak passwords are vulnerable.


### HTTP Request & Response


### Info Gathering
1. Attack a port that host a webpage. i.e. port 80


### Scanning
1. Set up some fake vulnerable vms to scan and test.
2. Scan for open virtual open ports, TCP, UDP, protocol for sending bits of data (packets).
3. HTTP port 80, HTTPS port 443, FTP port 21, SSH port 22, SMTP port 53, SMTP port 25. 65535 ports
4. Explore what software and version is on an open port.
5. TCP 3-way-handshake - 1. sync 2. sync/ack  3. ack Transmission Control Protocol
6. UDP - faster because it doesn't care if you receive the packets or not. - User Datagram Protocol


## References
[OWASP](https://cheatsheetseries.owasp.org/Glossary.html)
