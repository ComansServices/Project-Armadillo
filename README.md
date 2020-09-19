<p align="center">
<img width="300" src="https://i.imgur.com/pa5lugz.png" /><br>
A Web Dashbord Project-Armadillo - based on WebMap
</p>

## Table Of Contents
- [Usage](#usage)
- [Video](#video)
- [Features](#features)
- [PDF Report](#pdf-report)
- [XML Filenames](#xml-filenames)
- [CVE and Exploits](#cve-and-exploits)
- [Network View](#network-view)
- [RESTful API](#restful-api)
- [Third Parts](#third-parts)
- [Security Issues](#security-issues)
- [Contributors](#contributors)
- [Contacts](#contacts)


## Screenshot
<img src="https://" /><br>
<img src="https://" /><br>
<img src="https://" /><br>
<br>

## Usage
To build from source do the following:
```bash
$ git clone https://github.com/ComansServices/Project-armadillo
$ cd Project-Armadillo/docker
$ docker build -t armadillo .
$ mkdir /armadillo
$ docker run -d \
         --name armadillo \
         -h armadillo \
         -p 8000:8000 \
         -v /armadillo:/opt/xml \
         armadillo
         
$ # now you can run Nmap and save the XML Report on /armadillo
$ nmap -sT -A -T4 -oX /armadillo/myscan.xml 192.168.1.0/24

You can also pull a pre built image from dockerhub with:

$ docker pull exhoplex/armadillo
$ mkdir /armadillo
$ docker run -d \
         --name armadillo \
         -h armadillo \
         -p 8000:8000 \
         -v /armadillo:/opt/xml \
         exhoplex/armadillo
         
$ # now you can run Nmap and save the XML Report on /armadillo
$ nmap -sT -A -T4 -oX /armadillo/myscan.xml 192.168.1.0/24
```
Now point your browser to http://localhost:8000

### Generate new token
In order to access to the dashboard, you need a token. You can create a new token with:
```bash
$ docker exec -ti armadillo /root/token
```

### Upgrade from previous release
```bash
$ # stop running container
$ docker stop aramdillo

$ # remove container
$ docker rm armadillo

$ # build new image
$ cd Project-Armadillo/docker
$ docker build -t armadillo .

$ # run Armadillo
$  docker run -d \
         --name armadillo \
         -h armadillo \
         -p 8000:8000 \
         -v /tmp/armadillo:/opt/xml \
         armadillo
```

### Run without Docker
This project is designed to run on a Docker container. IMHO it isn't a good idea to run this on a custom Django installation,
but if you need it you can find all building steps inside the [Dockerfile]

## Features
- Import and parse Nmap XML files
- Run and Schedule Nmap Scan from dashboard
- Statistics and Charts on discovered services, ports, OS, etc...
- Inspect a single host by clicking on its IP address
- Attach labels on a host
- Insert notes for a specific host
- Create a PDF Report with charts, details, labels and notes
- Copy to clipboard as Nikto, Curl or Telnet commands
- Search for CVE and Exploits based on CPE collected by Nmap
- RESTful API

## Roadmap for v3.0

Many thanks to the original developer who created this code, I think it is a good framework, and I will be forking and taking over development of this software, and I will start to investigate and introduce the following for version 3.0 release.

I will re-name it project armadillo for now until I can think of a better name....

- [todo] Improve the login authentication process, include support for SSO/SAML and 2FA
- [todo] Re-write web code in Go Lang, make more robust and secure, get ready for cloudifaction
- [todo] Optimise python code for security and speed
- [todo] Create editable logo and identification options, develop a setup screen to change these items
- [todo] Write automation script for automated docker container creation
- [todo] create automated bash script for end to end isntallation with test data (docker, container, build , deploy
- [todo] create a new docker container for docker hub for easy download
- [working] Standardise look and feel, include more data feeds form other tools, improve exploit detection

## Roadmap for v2.3x
You love Armadillo and you know python? We need your help! This is what we want deploy for the v2.3:
- [todo] Improve template: try to define better the html template and charts
- [todo] Improve API: create a documentation/wiki about it
- [todo] Wiki: create WebMap User Guide on GitHub
- [working] Authentication or something that could blocks access to WebMap if != localhost
- [working] Scan diff: show difference between two scheduled nmap scan report
- [todo] Zaproxy: Perform web scan using the OWASP ZAP API

## Changes on v2.2
- fixed bug on missing services
- Run nmap from Armadillo
- Schedule nmap run
- Add custom NSE scripts section

## Changes on v2.1
- Better usage of Django template
- Fixed some Nmap XML parse problems
- Fixed CVE and Exploit collecting problems
- Add new Network View
- Add RESTful API

## PDF Report


## XML Filenames
When creating the PDF version of the Nmap XML Report, the XML filename is used as document title on the first page.
Aramadillo will replace some parts of the filename as following:

- `_` will replaced by a space (` `)
- `.xml` will be removed

Example: `ACME_Ltd..xml`<br>
PDF title: `ACME Ltd.`

## CVE and Exploits
thanks to the amazing API services by circl.lu, Armadillo is able to looking for CVE and Exploits for each CPE collected by Nmap.
Not all CPE are checked over the circl.lu API, but only when a specific version is specified
(for example: `cpe:/a:microsoft:iis:7.5` and not `cpe:/o:microsoft:windows`).

## Network View


## RESTful API
From `v2.1` Armadillo has a RESTful API frontend that makes users able to query their scan files with something like:

```bash
curl -s 'http://localhost:8000/api/v1/scan?token=<token>'

    "armadillo_version": "v2.4/master",
    "scans": {
        "scanme.nmap.org.xml": {
            "filename": "scanme.nmap.org.xml",
            "startstr": "Sun Nov  4 16:22:46 2018",
            "nhost": "1",
            "port_stats": {
                "open": 42,
                "closed": 0,
                "filtered": 0
            }
        },
        "hackthebox.xml": {
            "filename": "hackthebox.xml",
            "startstr": "Mon Oct  8 20:56:32 2018",
            "nhost": "256",
            "port_stats": {
                "open": 67,
                "closed": 0,
                "filtered": 2
            }
        }
    }
}
```

A user can get information about a single scan by append to the URL the XML filename:

```bash
curl -v 'http://localhost:8000/api/v1/scan/hackthebox.xml?token=<token>'

{
    "file": "hackthebox.xml",
    "hosts": {
        "10.10.10.2": {
            "hostname": {},
            "label": "",
            "notes": ""
        },
        "10.10.10.72": {
            "hostname": {
                "PTR": "streetfighterclub.htb"
            },
            "label": "",
            "notes": ""
        },
        "10.10.10.76": {
            "hostname": {},
            "label": "",
            "notes": ""
        },
        "10.10.10.77": {
            "hostname": {},
            "label": "Vulnerable",
            "notes": "PHNwYW4gY2xhc3M9ImxhYmVsIGdyZWVuIj5SRU1FRElBVElPTjwvc3Bhbj4gVXBncmFkZSB0byB0aGUgbGF0ZXN0IHZlcnNpb24g"
        },
...
```

and he can get all information about a single host by append the IP address to URL:

```bash
curl -v 'http://localhost:8000/api/v1/scan/hackthebox.xml/10.10.10.87?token=<token>'

    "file": "hackthebox.xml",
    "hosts": {
        "10.10.10.87": {
            "ports": [
                {
                    "port": "22",
                    "name": "ssh",
                    "state": "open",
                    "protocol": "tcp",
                    "reason": "syn-ack",
                    "product": "OpenSSH",
                    "version": "7.5",
                    "extrainfo": "protocol 2.0"
                },
                {
                    "port": "80",
                    "name": "http",
                    "state": "open",
                    "protocol": "tcp",
                    "reason": "syn-ack",
                    "product": "nginx",
                    "version": "1.12.2",
                    "extrainfo": ""
                },
                {
                    "port": "8888",
                    "name": "sun-answerbook",
                    "state": "filtered",
                    "protocol": "tcp",
                    "reason": "no-response",
                    "product": "",
                    "version": "",
                    "extrainfo": ""
                }
            ],
            "hostname": {},
            "label": "Checked",
            "notes": "",
            "CVE": [
                {
                    "Modified": "2018-08-17T15:29:00.253000",
                    "Published": "2018-08-17T15:29:00.223000",
                    "cvss": "5.0",
                    "cwe": "CWE-200",
                    "exploit-db": [
                        {
                            "description": "OpenSSH 7.7 - Username Enumeration. CVE-2018-15473. Remote exploit for Linux platform",
                            "file": "exploits/linux/remote/45233.py",
                            "id": "EDB-ID:45233",
                            "last seen": "2018-08-21",
                            "modified": "2018-08-21",
                            "platform": "linux",
                            "port": "",
                            "published": "2018-08-21",
                            "reporter": "Exploit-DB",
                            "source": "https://www.exploit-db.com/download/45233/",
                            "title": "OpenSSH 7.7 - Username Enumeration",
                            "type": "remote"
                        },
                        {
                            "id": "EDB-ID:45210"
                        }
                    ],
                    "id": "CVE-2018-15473",
                    "last-modified": "2018-11-02T06:29:06.993000",
                    "metasploit": [
...
```

## Third Parts
- [Django](https://www.djangoproject.com)
- [Materialize CSS](https://materializecss.com)
- [Clipboard.js](https://clipboardjs.com)
- [Chart.js](https://www.chartjs.org)
- [Wkhtmltopdf](https://wkhtmltopdf.org)
- [API cve.circl.lu](https://cve.circl.lu)
- [vis.js](http://visjs.org/)

## Security Warning
This application needs to be properly deployed and secured, I advise using TINC or GVPE to create a secure Management LAN , so you can securely access this application over the wire. Please use a firewall and block direct access from the internet to this application for now as a precaution.

Secure Usage Scenario 1: Deploy Application on a VPS, use a firewall to block all incoming ports, use TINC or GvPE to create a VPN Network to VPS. Brows to web page using secured VPN connection to the VPS. (Hint: you can also create a VPN into a network you want to scan and tear it down later)

Secure Usage Scenario 2: Deploy application to a raspberry pi, connect pi to a network for scans, then browse to pi over your local lan to view resuts.

This application has not been properly PEN tested for external use on the internet just yet. I will be doing this optimisation shortly, but for now use only on a private and secure managemnet network.

I will include a script to help automate the creation of such a LAN in a future release.

## Contributors
This project is currently a beta, and I'm not super skilled on Django so, every type of contribution is appreciated.
I'll mention all contributors on the [CONTRIBUTORS](CONTRIBUTORS.md) file.
