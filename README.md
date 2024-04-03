# Information Gathering from Kali Linux

## Introduction
Information gathering is a crucial phase in any cybersecurity assessment or penetration testing process. Kali Linux provides a wide range of tools and utilities specifically designed for reconnaissance and gathering information about targets. In this guide, we'll explore some of the commonly used tools and techniques for information gathering in Kali Linux.

## Tools and Techniques

### 1. Nmap
[Nmap](https://nmap.org/) is a powerful network scanning tool used for discovering hosts and services on a computer network. It allows for port scanning, service version detection, and operating system detection.

#### Command Example:
```bash
nmap -sS -A target_ip
