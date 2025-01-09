# Arper: BETA Project

Welcome to the **Arper** project! 🚀

## Overview

**Arper** is a BETA project designed to demonstrate ARP poisoning and packet sniffing using Python and Scapy. This project is still under development and will continue to evolve, with new features and improvements added over time.

## ⚠️ Disclaimer

This tool is intended for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission before testing on any networks or devices you don't own.

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
```

2. Change to the project directory:
```bash
cd arper
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
sudo python3 arper.py <victim_ip> <gateway_ip> <interface>
```

Example:
```bash
sudo python3 arper.py 192.168.100.3 192.168.100.13 wlan0
```

## Requirements

- Python 3.x
- Scapy library
- Root/Administrator privileges
- Network interface in monitor mode

## Contributing

We welcome contributions to improve and expand Arper! If you have ideas, bug reports, or feature requests, please:

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

```
MIT License

Copyright (c) 2025 scrollDynasty

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Acknowledgments

A big thank you to:
- The open-source community for their invaluable tools and resources
- All contributors who help improve this project
- Scapy development team for their excellent packet manipulation library

## Stay Connected

Stay tuned for more updates as we continue to develop and enhance Arper! 💻✨

---
Made with ❤️ by scrollDynasty
