"""Enumeration module for ADRecon.

This module contains helper functions and enumeration workflows for
Active Directory enumeration and data collection.
"""

from typing import Any, Dict, List, Optional


def get_enumeration_modules() -> List[str]:
    """Return the list of available enumeration modules."""
    return [
        'users',
        'computers',
        'groups',
        'ous',
        'gpos',
        'trusts'
    ]


def enumerate_users(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> List[Dict[str, Any]]:
    """Enumerate domain users and return a list of user records."""
    raise NotImplementedError('User enumeration is implemented in the enumeration module.')


def enumerate_computers(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> List[Dict[str, Any]]:
    """Enumerate domain computers."""
    raise NotImplementedError('Computer enumeration is implemented in the enumeration module.')


def enumerate_groups(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> List[Dict[str, Any]]:
    """Enumerate domain groups."""
    raise NotImplementedError('Group enumeration is implemented in the enumeration module.')


def enumerate_ous(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> List[Dict[str, Any]]:
    """Enumerate organizational units."""
    raise NotImplementedError('OU enumeration is implemented in the enumeration module.')


def enumerate_gpos(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> List[Dict[str, Any]]:
    """Enumerate GPOs."""
    raise NotImplementedError('GPO enumeration is implemented in the enumeration module.')


def enumerate_trusts(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> List[Dict[str, Any]]:
    """Enumerate domain trusts."""
    raise NotImplementedError('Trust enumeration is implemented in the enumeration module.')


def get_enumeration_summary(domain: str, ip: str, username: str, password: str, protocol: str = 'winrm') -> Dict[str, Any]:
    """Return an overall enumeration summary and object counts."""
    raise NotImplementedError('Enumeration summary is implemented in the enumeration module.')
