# Network Vulnerability Scanner

A command line tool that scans a target host for common security vulnerabilities.

## What it checks

- **Open ports** — identifies which ports are accepting connections and grabs service banners to identify running software and versions
- **HTTP security headers** — checks for missing headers that leave users exposed to common attacks
- **Open redirects** — tests whether the server blindly follows external redirect parameters

## Installation

Clone the repository and install dependencies:

git clone https://github.com/yourusername/network-scanner.git;
cd network-scanner;
python -m venv venv;
venv\Scripts\activate;
pip install -r requirements.txt;

## Usage

Basic scan using common ports:

python main.py <host>

Scan specific ports:

python main.py <host> --ports 80 443 22

## Example

python main.py scanme.nmap.org

## Project Structure

- `scanner.py` — TCP port scanning with service banner grabbing
- `headers.py` — HTTP security header checks
- `redirects.py` — open redirect detection
- `reporter.py` — generates timestamped report files
- `main.py` — CLI interface

## Legal

Only scan hosts you have permission to scan. This tool was tested against scanme.nmap.org, a server maintained by the nmap project for legal scanning practice.
