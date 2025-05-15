# ip-block-validator

# SpainIPChecker

A tool for checking if domains are being blocked by ISPs in Spain, specifically detecting LaLiga-related IP blocks.

## Overview
This tool scans a list of domains to determine if they are being blocked by DigiSpain ISP in Spain. It uses residential proxies from GeoNode to route traffic through the target ISP and detects specific blocking patterns.

## Requirements
- Python 3.7+
- GeoNode proxy credentials

## Installation
1. Clone this repository
git clone https://github.com/yourusername/SpainIPChecker.git
cd SpainIPChecker
