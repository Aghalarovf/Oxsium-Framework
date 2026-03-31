# Oxsium-Framework

Oxsium-Framework is an Active Directory reconnaissance and operations interface with protocol-based connection handling and modular enumeration views.

## Features

- Multi-protocol connect flow (WinRM, SSH, SMB, PSExec)
- Local session mode
- AD modules: Users, Computers, OUs, GPOs, Groups, Trusts
- Enumeration and shell UI views

## Quick Start

1. Install dependencies:

   `pip install -r requirements.txt`

2. Run backend:

   `python connection.py`

3. Open `Oxsium-Framework.html` in your browser or serve it via a local static server.

## Repository Structure

- `connection.py` - Flask backend API
- `Oxsium-Framework.html` - Main UI shell
- `Oxsium-Framework.css` - Styling
- `Oxsium-Framework.js` - Frontend logic
- `users.py`, `computers.py`, `ou.py`, `gpo.py`, `groups.py`, `trust.py` - AD modules
- `local_ad.py` - Local session AD data collection
- `requirements.txt` - Python dependencies
