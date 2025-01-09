# Arper: BETA Project

![Arper Logo](logo.png)

Welcome to the **Arper** project! 🚀

## Overview
**Arper** is a BETA project designed to demonstrate ARP poisoning and packet sniffing using Python and Scapy. This project is still under development and will continue to evolve, with new features and improvements added over time.

## Features
- ARP poisoning
- Packet sniffing
- Real-time packet analysis
- Cross-platform support (Windows, Linux, macOS)

## Installation
To get started with **Arper**, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/scrollDynasty/arp-snif
2. Change to the project directory
   ```bash
   cd arper
3. Install dependencies
   ```bash
   pip install -r requirements.txt
4. Using
   ```bash
   sudo python3 arper.py <victim_ip> <gateway_ip> <interface>
5. Example:
   ```bash
   sudo python3 arper.py 192.168.100.3 192.168.100.13 wlan0
