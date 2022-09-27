# Project Melon (In Progress..)

This is a collection of all security related tools that I happen to go over while also mentioning any external repos.

- [Project Melon (In Progress..)](#project-melon-in-progress)
- [Project Structure](#project-structure)
- [Knowledge Gates](#knowledge-gates)
- [Tools\Sites](#toolssites)
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
| Blueteamlabs        | `soon`                                                                                                                       | https://cyberdefenders.org/                                       | `blueteam` `learning` `practice`                                |
| TryHackme           | Great free source for blue team & red team learning paths with a practical expierence                                        | https://tryhackme.com/                                            | `free` `blue tean` `red team` `learning` `practice`             |
| PicoCTF             | Great free source for CTF & red team training covering all aspects from reverse engineering to web penteration               | https://picoctf.org/                                              | `free`  `red team` `learning` `CTF` `practice`                  |
| HackTheBox          | Great free source for CTF & red team training and a source of certificates                                                   | https://www.hackthebox.com/                                       | `free`  `red team` `learning` `CTF` `certifications` `practice` |

# Tools\Sites

## Web related

### Sites


| Name       | Value                                                                                                                                                                      | Link                                     | tag                          |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------ |
| Juice shop | Modren insecure web app that you can test your pentesting skills on.(website is no longer online, you might need to host it on your machine the docker image is available) | https://github.com/juice-shop/juice-shop | `free` `red team` `learning` |

### Tools


| Name      | Value                                         | Link                             | Tags                     |
| ----------- | ----------------------------------------------- | ---------------------------------- | -------------------------- |
| Burpsuite | All in one tool for web appication pentesting | https://portswigger.net/         | `free` `paid` `red team` |
| Arachni   | Vulnerability scanning and reporting tool     | https://www.arachni-scanner.com/ | `free` `scanning`        |

## Forensics

### Sites


| Name      | Value                                                                                                            | Link                               | Tag                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------ | ----------------------------- |
| Echotrail | Insight on windows proccess and servicess (e.g.. what is svchost.exe and it's parents\relatives and source path) | https://www.echotrail.io/          | `forensics`                 |
| LOLBAS    | Living of the land binaries,                                                                                     | https://lolbas-project.github.io/# | `forensics`                 |
| Wigle.net | Wigle.net is a website that consolidates location and other data on wireless networks around the world           | [Wigle](https://www.wigle.net/)    | `forensics`<br />`networks` |

### Tools

In general [Eric zimmerman tools](https://ericzimmerman.github.io/) are a great source for windows forensics tools where to goes through: jumplists, prefetches, appCompatability cache, event logs, link files, Master file table, shell bags, srum data and more !


| Name                  | Value                                                                             | Link                                                                              | Tag                       |
| ----------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------- |
| EventLogExplorer      | Easier and corruption tolerant log viewer, with ability to create custome columns | [EventLogExplorer](https://eventlogxp.com/)                                                                  | `forensics` `windows`     |
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

## Malware analysis

I am no expert in this so i need help here 😄

> Most tools here are from the LetsDefend malware analysis course

### Sites

- Anlyz
- Any.run ( low volume)
- tri.age (high volume) ( https://tria.ge/ )
- Comodo Valkyrie
- Cuckoo
- Hybrid Analysis
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

### Tools

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


| Name      | Value                        | Link                                                      | Tags                   |
| ----------- | ------------------------------ | ----------------------------------------------------------- | ------------------------ |
| AbuseIPDB | Check IP reputation          | [AbuseIpDB](https://www.abuseipdb.com/)                   | `network` `reputation` |
| Talos     | IP reputation (mostly email) | [Talos](https://talosintelligence.com/reputation_center/) | `network` `reputation` |
| MxTools   | records lookups              | [MxTools](https://mxtoolbox.com/)                         | `network` `reputation` |

### Tools

# Extras

* https://malware-traffic-analysis.net/
* (Threat inteliigence sources) https://github.com/hslatman/awesome-threat-intelligence
* (pcap visualizer) https://github.com/Srinivas11789/PcapXray
* (security lists) https://github.com/danielmiessler/SecLists
* https://github.com/projectdiscovery/nuclei
* https://github.com/RsaCtfTool/RsaCtfTool
* https://www.shodan.io/
