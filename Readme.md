# Project Melon (In Progress..)

This is a collection of all security related tools that I happen to go over while also mentioning any external repos.

- [Project Melon (In Progress..)](#project-melon-in-progress)
- [Project Structure](#project-structure)
- [Knowledge Gates](#knowledge-gates)
- [Tools\\Sites](#toolssites)
  - [Web related](#web-related)
    - [Sites](#sites)
    - [Tools](#tools)
  - [Forensics](#forensics)
    - [Sites](#sites-1)
    - [Tools](#tools-1)
  - [Malware analysis](#malware-analysis)
    - [Sites](#sites-2)
    - [Tools](#tools-2)
      - [Some debuggers:](#some-debuggers)
      - [Network activity monitoring:](#network-activity-monitoring)
      - [Process monitoring tools:](#process-monitoring-tools)
      - [Other Tools :](#other-tools-)
  - [Cracking](#cracking)
    - [Sites](#sites-3)
    - [Tools](#tools-3)
  - [Networks](#networks)
    - [Sites](#sites-4)
    - [Tools](#tools-4)
- [Extras](#extras)

---

---

# Project Structure

This repo will be divided per tool category and further down with it being a tool or a website. tags are added to everything to make it easier and quicker to find.

# Knowledge Gates


| Name                | Value                                                                                                                        | Link                                                              | Tags                                                            |
| :-------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ----------------------------------------------------------------- |
| LetsDefend platform | Great free learning path for aspiring SOC analysts with access case managmet to solve Alerts that SOC analysts may encounter | https://app.letsdefend.io/<br />https://app.letsdefend.io/academy | `free` `blueteam` `learning`                                    |
| Cyberdefenders      | `soon`                                                                                                                       | https://cyberdefenders.org/                                       | `blueteam` `learning` `practice`                                |
| Blueteamlabs        | `soon`                                                                                                                       | https://blueteamlabs.online/                                      | `blueteam` `learning` `practice`                                |
| TryHackme           | Great free source for blue team & red team learning paths with a practical expierence                                        | https://tryhackme.com/                                            | `free` `blue tean` `red team` `learning` `practice`             |
| PicoCTF             | Great free source for CTF & red team training covering all aspects from reverse engineering to web penteration               | https://picoctf.org/                                              | `free`  `red team` `learning` `CTF` `practice`                  |
| HackTheBox          | Great free source for CTF & red team training and a source of certificates                                                   | https://www.hackthebox.com/                                       | `free`  `red team` `learning` `CTF` `certifications` `practice` |

# Tools\Sites

## Web related

### Sites


| Name       | Value                                                                                                                                                                      | Link                                     | tag                          |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------ |
| Juice shop | Modren insecure web app that you can test your pentesting skills on.(website is no longer online, you might need to host it on your machine the docker image is available) | https://github.com/juice-shop/juice-shop | `free` `red team` `learning` |
| URLVOID    | Website reputation checker                                                                                                                                                 | https://www.urlvoid.com/                 | `reputation` `scanning`      |
| Checkphish | AI-powered scanner that analyzes the safety of URLs                                                                                                                        | https://checkphish.ai/                   | `reputation` `scanning`      |

### Tools


| Name      | Value                                         | Link                             | Tags                     |
| ----------- | ----------------------------------------------- | ---------------------------------- | -------------------------- |
| Burpsuite | All in one tool for web appication pentesting | https://portswigger.net/         | `free` `paid` `red team` |
| Arachni   | Vulnerability scanning and reporting tool     | https://www.arachni-scanner.com/ | `free` `scanning`        |

## Forensics

### Sites


| Name                                                     | Value                                                                                                            | Link                                                    | Tag                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- | ------------------------------------------- |
| Echotrail                                                | Insight on windows proccess and servicess (e.g.. what is svchost.exe and it's parents\relatives and source path) | [echotrail](https://www.echotrail.io/https:/)           | `forensics`                               |
| LOLBAS                                                   | Living of the land binaries,                                                                                     | [lolbas](https://lolbas-project.github.io/#https:/)     | `forensics`                               |
| Wigle.net                                                | Wigle.net is a website that consolidates location and other data on wireless networks around the world           | [Wigle](https://www.wigle.net/)                         | `forensics`<br />`networks`               |
| CFReDS<br />(Computer Forensic Reference DataSet Portal) | Forensic images for training from NIST                                                                           | [NIST forensic images](https://cfreds.nist.gov/https:/) | `forensics`<br />`images`<br />`datasets` |

### Tools

In general [Eric zimmerman tools](https://ericzimmerman.github.io/) are a great source for windows forensics tools where to goes through: jumplists, prefetches, appCompatability cache, event logs, link files, Master file table, shell bags, srum data and more !


| Name                  | Value                                                                             | Link                                                                              | Tag                       |
| ----------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------- |
| EventLogExplorer      | Easier and corruption tolerant log viewer, with ability to create custome columns | [EventLogExplorer](https://eventlogxp.com/)                                       | `forensics` `windows`     |
| Kape                  | Triage Image collection tool                                                      | [Eric zimmerman tools](https://ericzimmerman.github.io)                           | `forensics` `windows`     |
| Registery Explorer    | View registery & find deleted keys with shortcuts to important forensic data.     | [Eric zimmerman tools](https://ericzimmerman.github.io/)                          | `forensics` `windows`     |
| TimeLine explorer     | Excel Like viewer with a great filtiring ability                                  | [Eric zimmerman tools](https://ericzimmerman.github.io/)                          | `forensics` `windows`     |
| bstrings              | Strings(Linux) like tool but for windows                                          | [Eric zimmerman tools](https://ericzimmerman.github.io/)                          | `forensics` `windows`     |
| Photorec              | Header based\carving data recovery                                                | [Photorec](https://www.cgsecurity.org/wiki/TestDisk_Download)                     | `forensics` `recovery`    |
| Autopsy               | Case\image investigation & data recovery                                          | [Autopsy](https://www.autopsy.com/download/)                                      | `forensics` `recovery`    |
| Bulk Extractor        | carving tool with a special plugin to carve for logs                              | [Bulk Extractor](https://github.com/simsong/bulk_extractor)                       | `forensics` `recovery`    |
| Arsenal Image mounter | Mount images and investigate them without overwriting the original data           | [Arsenal Recon](https://arsenalrecon.com/downloads/)                              | `forensics`               |
| Browsing History view | view browsing history for multiple broswers like chrome\opera\firefox             | [Browsing History view](https://www.nirsoft.net/utils/browsing_history_view.html) | `forensics`               |
| Mail OST\PST viewers  | nice to the eye email viewer                                                      | [Kernel Data Recovery tools](https://www.nucleustechnologies.com/free-tools.html) |                           |
| USB Detective         | Overall USB forensics                                                             | [USB Detective](https://usbdetective.com/)                                        | `forensics` `free` `paid` |
| WinPmem               | Memory acquestion                                                                 | [WinPmem](https://github.com/Velocidex/WinPmem)                                   | `forensic`                |
| DumpIt                | Memory acquestion                                                                 |                                                                                   | `forensic`                |

## Malware analysis

I am no expert in this so i need help here 😄

> Most tools here are from the LetsDefend malware analysis course So Thank you ! ❤️

### Sites

- Anlyz
- Any.run (low volume)
- tri.age (high volume) ( https://tria.ge/ )
- Threat Zone ( https://app.threat.zone/plans )
- Comodo Valkyrie
- Cuckoo
- Hybrid Analysis ( https://www.hybrid-analysis.com/ )
- Docguard ( https://app.docguard.io/ )
- Intezer Analyze
- SecondWrite Malware Deepview
- Jevereg
- IObit Cloud
- BinaryGuard
- BitBlaze
- SandDroid
- Joe Sandbox
- AMAaaS
- IRIS-H
- Gatewatcher Intelligence
- Hatching Triage
- InQuest Labs
- Manalyzer
- SandBlast Analysis
- SNDBOX
- firmware
- opswat
- virusade
- virustotal
- malware config
- malware hunter team
- virscan
- jotti
- [Eicar](https://www.eicar.org/download-anti-malware-testfile/)

### Tools

* Sandboxie-plus ([https://sandboxie-plus.com/](https://https://sandboxie-plus.com/))

#### Some debuggers:

- Ollydbg
- X64dbg
- Windbg
- Radare2

#### Network activity monitoring:

- Wireshark
- Fiddler
- Burp Suite

#### Process monitoring tools:

- Process Hacker
- Process Explorer (SysInternals)
- Procmon (SysInternals)

#### Other Tools :

- SysInternal Tools
- CFF Explorer
- PEView
- PEStudio
- TriDNet
- BinText
- PEiD
- Regshot (Takes registery snapshots before and after malware activation)
- HashMyFiles

## Cracking

### Sites


| Name      | Value                                                                                                                                                      | Link                              | Tag    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------- | -------- |
| CyberChef | your go-to tool to decode\decrypt cryptographic test with the amazing magic functionality which can try to brute force algorithms on an unknown ciphertext | https://gchq.github.io/CyberChef/ | `free` |
| Decode    | similar to cyber chef and probably better in some areas.<br />cipher\hash identifiers                                                                      | https://dcode.fr/en               | `free` |

### Tools

> Thank you LetsDefend


| Name                 | Value                                                                                                                                                                                                                                                                                | Link                                                                           | Tag     |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | --------- |
| Aircrack-ng          | aircrack-ng is an 802.11a/b/g WEP/WPA cracking program that can recover a 40-bit, 104-bit, 256-bit or 512-bit WEP key once enough encrypted packets have been gathered. Also it can attack WPA1/2 networks with some advanced methods or simply by brute force.                      | [Link](https://github.com/aircrack-ng/aircrack-ng)  available in linux library | `linux` |
| John the RipperDecod | John the Ripper is a tool designed to help systems administrators to find weak (easy to guess or crack through brute force) passwords, and even automatically mail users alert them about it, if it is desired. Runs on 15 different platforms including Unix, Windows, and OpenVMS. | available in linux library                                                     | `linux` |
| L0phtCrack           | a tool for cracking Windows passwords. It uses rainbow tables, dictionaries, and multiprocessor algorithms.                                                                                                                                                                          | available in linux library                                                     | `linux` |
| Hashcat              | Hashcat supports five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, and has facilities to help distribute password cracking.                                             | available in linux library                                                     | `linux` |
| Ncrack               | a tool for cracking network authentication. It can be used on Windows, Linux, and BSD. It was built to help companies secure their networks by proactively testing all their hosts and networking devices for poor passwords.                                                        | available in linux library                                                     | `linux` |
| Hydra                | Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.                                                                                                                                    | available in linux library                                                     | `linux` |

## Networks

### Sites


| Name             | Value                                                               | Link                                                            | Tags                           |
| ------------------ | --------------------------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------- |
| AbuseIPDB        | Check IP reputation                                                 | [AbuseIpDB](https://www.abuseipdb.com/)                         | `network` `reputation`         |
| Talos            | IP reputation (mostly email)                                        | [Talos](https://talosintelligence.com/reputation_center/)       | `network` `reputation`         |
| MxTools          | records lookups                                                     | [MxTools](https://mxtoolbox.com/)                               | `network` `reputation`         |
| UrlScan.io       | scan a website or check previous scans with images from the website | [UrlScan.io](https://urlscan.io/)                               | `network``reputation`          |
| ZoomEye          | Similar to shodan with vulnarbility scanning                        | [zoomEye](https://www.zoomeye.org/)                             | `network`<br />`vulnerability` |
| Alienvault       | Open threat intel and reputation checker                            | [alienvault.com/](https://otx.alienvault.com/https:/)           | `network` `reputation`         |
| X-Force Exchange | Open threat intel by IBM                                            | [exchange.xforce](https://exchange.xforce.ibmcloud.com/https:/) | `network` `reputation`         |
| IPVoid           | IP block list checker                                               | [IPvoid](https://www.ipvoid.com/https:/)                        | `network` `reputation`         |
| IPInfo           | Get more details about an IP like Geo Location and deeper details   | [IPinfo.io](https://ipinfo.io/https:/)                          | `network`                      |

### Tools


| Name          | Value                                                                                                                                                                                         | Link                                                        | Tags                    |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------- |
| Wireshark     | View and analyze pcap files                                                                                                                                                                   | [Wireshark](https://www.wireshark.org/)                     | `netowrk`               |
| Brim          | Uses with wireshark to open big pcap files fastly & clearly, where it summerize packets using the zeek(bro) logs and allow for instant extraction of targeted pcaps with a click of a button. | [Brim](https://www.brimdata.io/download/)                   | `network`               |
| Network miner | similar to wireshark but with quicker to access menues with free & paid version                                                                                                               | [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) | `network` `free` `paid` |

# Extras

* https://www.phishtool.com/ ( a local tool to analyze phishing emails)
* https://malware-traffic-analysis.net/
* https://github.com/nsacyber/Mitigating-Web-Shells
* (Threat inteliigence sources) https://github.com/hslatman/awesome-threat-intelligence
* https://binaryedge.io/ ( Threat Intel.)
* https://www.crowdsec.net/ ( Threat Intel & scanning engine  )
* https://www.cvedetails.com/ (CVE details)
* (pcap visualizer) https://github.com/Srinivas11789/PcapXray
* (security lists) https://github.com/danielmiessler/SecLists
* https://github.com/projectdiscovery/nuclei
* https://github.com/RsaCtfTool/RsaCtfTool
* https://www.shodan.io/
* [The missing verclsid.exe documentation | by Henri Hambartsumyan | FalconForce | Medium](https://medium.com/falconforce/the-missing-verclsid-exe-documentation-7080757e9acf)
* https://offsec.tools/ ( Security tools list browser )
* https://www.vmray.com/
