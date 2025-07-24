#!/usr/bin/env python3
"""
gimmePATz - Personal Access Token recon tool

This script automatically detects and analyzes GitHub PATs and NPM tokens
by parsing their format and validating against appropriate services.

"""

import argparse
import json
import os
import subprocess
import requests
import sys
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import concurrent.futures
from urllib.parse import urlparse
import base64
import hashlib

# Version information
__version__ = "0.3.1"
__author__ = "@6mile"

class TokenDetector:
    """Automatic token type detection and classification"""
    
    def __init__(self):
        self.token_patterns = {
            'github': [
                r'ghp_[a-zA-Z0-9]{36}',  # GitHub personal access token
                r'gho_[a-zA-Z0-9]{36}',  # GitHub OAuth token
                r'ghu_[a-zA-Z0-9]{36}',  # GitHub user token
                r'ghs_[a-zA-Z0-9]{36}',  # GitHub server token
                r'ghr_[a-zA-Z0-9]{36}',  # GitHub refresh token
                r'github_pat_[a-zA-Z0-9_]{82}',  # GitHub fine-grained PAT
            ],
            'npm': [
                r'npm_[a-zA-Z0-9]{36}',  # Standard npm token
                r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # Legacy UUID
                r'//registry\.npmjs\.org/:_authToken=([a-zA-Z0-9\-_+/=]{20,})',  # .npmrc format
            ],
            'docker': [
                r'dckr_pat_[a-zA-Z0-9\-_]{56}',  # Docker Hub PAT
            ],
            'gitlab': [
                r'glpat-[a-zA-Z0-9\-_]{20}',  # GitLab personal access token
                r'gldt-[a-zA-Z0-9\-_]{20}',   # GitLab deploy token
            ],
            'generic': [
                r'[a-zA-Z0-9+/]{40,}={0,2}',  # Generic base64 token
                r'[a-f0-9]{32,}',  # Generic hex token
            ]
        }
    
    def detect_token_type(self, token: str) -> str:
        """Detect token type based on format"""
        token = token.strip()
        
        # Check each token type
        for token_type, patterns in self.token_patterns.items():
            for pattern in patterns:
                if re.match(pattern, token, re.IGNORECASE):
                    return token_type
        
        # Additional heuristic checks
        if len(token) >= 20:
            if token.startswith('npm_'):
                return 'npm'
            elif token.startswith(('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')):
                return 'github'
            elif token.startswith('glpat-'):
                return 'gitlab'
            elif token.startswith('dckr_'):
                return 'docker'
            elif len(token) >= 32 and token.isalnum():
                # Check if it's all hex characters
                if all(c in '0123456789abcdefABCDEF' for c in token):
                    return 'generic'
            elif len(token) >= 20:
                # Check if it looks like a base64 token
                if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in token):
                    return 'npm'  # Could be npm token in different format
        
        return 'unknown'
    
    def extract_tokens_from_text(self, text: str, source: str = "") -> List[Dict]:
        """Extract all types of tokens from text"""
        found_tokens = []
        
        # Extract all token patterns
        for token_type, patterns in self.token_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    token = match.group(1) if match.groups() else match.group(0)
                    token = self.clean_token(token)
                    
                    if self.is_valid_token_format(token):
                        found_tokens.append({
                            'token': token,
                            'type': token_type,
                            'source': source,
                            'pattern': pattern,
                            'context': self.get_context(text, match.start(), match.end())
                        })
        
        # Additional environment variable patterns
        env_patterns = [
            r'(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
            r'(?:NPM_TOKEN|NPM_AUTH_TOKEN)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_+/=]{20,})["\']?',
            r'(?:GITLAB_TOKEN|GL_TOKEN)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
            r'(?:DOCKER_TOKEN|DOCKERHUB_TOKEN)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
        ]
        
        for pattern in env_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                token = match.group(1)
                token = self.clean_token(token)
                
                if self.is_valid_token_format(token):
                    detected_type = self.detect_token_type(token)
                    found_tokens.append({
                        'token': token,
                        'type': detected_type,
                        'source': source,
                        'pattern': pattern,
                        'context': self.get_context(text, match.start(), match.end())
                    })
        
        return found_tokens
    
    def clean_token(self, token: str) -> str:
        """Clean extracted token"""
        # Remove common prefixes and suffixes
        token = re.sub(r'^.*?:', '', token)  # Remove key: prefix
        token = re.sub(r'^["\']|["\']$', '', token)  # Remove quotes
        token = token.strip()
        return token
    
    def is_valid_token_format(self, token: str) -> bool:
        """Check if token has valid format"""
        if len(token) < 20:
            return False
        
        # Check for common false positives
        false_positives = [
            'example', 'placeholder', 'your_token', 'token_here',
            'insert_token', 'npm_token', 'your_npm_token', 'github_token',
            'xxxxx', 'aaaaa', 'bbbbb', 'ccccc', 'ddddd', 'eeeee'
        ]
        
        if token.lower() in false_positives:
            return False
        
        # Must contain mostly alphanumeric characters
        if not re.match(r'^[a-zA-Z0-9\-_=+/]+$', token):
            return False
        
        return True
    
    def get_context(self, text: str, start: int, end: int, context_chars: int = 50) -> str:
        """Get context around the found token"""
        context_start = max(0, start - context_chars)
        context_end = min(len(text), end + context_chars)
        context = text[context_start:context_end]
        return context.replace('\n', '\\n').replace('\r', '\\r')


class NPMTokenChecker:
    """NPM Token validation and enumeration functionality with enhanced access detection"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.npm_registry_url = "https://registry.npmjs.org"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'gimmepatz-npm/1.0',
            'Accept': 'application/json'
        })

    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp"""
        if self.debug or level in ["ERROR", "WARN", "FOUND"]:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")

    def validate_npm_token(self, token: str) -> Tuple[bool, Dict]:
        """Validate token against npm registry"""
        try:
            # Clean token of any prefixes but keep npm_ if it's there
            clean_token = token.strip()
            
            # Test token by trying to access whoami endpoint
            headers = {
                'Authorization': f'Bearer {clean_token}',
                'Accept': 'application/json'
            }
            
            response = self.session.get(
                f"{self.npm_registry_url}/-/whoami",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return True, {
                    'username': data.get('username', 'unknown'),
                    'valid': True,
                    'permissions': self.check_npm_token_permissions(clean_token)
                }
            elif response.status_code == 401:
                return False, {'valid': False, 'error': 'Invalid token'}
            else:
                return False, {'valid': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            self.log(f"NPM token validation error: {str(e)}", "ERROR")
            return False, {'valid': False, 'error': str(e)}

    def check_npm_token_permissions(self, token: str) -> Dict:
        """Check what permissions the NPM token has"""
        permissions = {
            'read': False,
            'publish': False,
            'admin': False,
            'details': {}
        }
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            
            # Test read permissions by accessing a public package
            response = self.session.get(
                f"{self.npm_registry_url}/lodash",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                permissions['read'] = True
            
            # Check token details and scope
            token_response = self.session.get(
                f"{self.npm_registry_url}/-/npm/v1/tokens",
                headers=headers,
                timeout=10
            )
            
            if token_response.status_code == 200:
                token_data = token_response.json()
                # Look for current token in the list
                for token_info in token_data.get('objects', []):
                    token_key = token_info.get('key', '')
                    if token.endswith(token_key[-8:]):  # Match last 8 chars
                        permissions['details'] = {
                            'readonly': token_info.get('readonly', False),
                            'automation': token_info.get('automation', False),
                            'cidr_whitelist': token_info.get('cidr_whitelist', []),
                            'created': token_info.get('created', ''),
                            'updated': token_info.get('updated', '')
                        }
                        
                        # If not readonly, it has publish permissions
                        if not token_info.get('readonly', True):
                            permissions['publish'] = True
                        break
            
            # Try to check specific package permissions by attempting to get package access
            # This is a more direct way to check what the token can actually access
            whoami_response = self.session.get(
                f"{self.npm_registry_url}/-/whoami",
                headers=headers,
                timeout=5
            )
            
            if whoami_response.status_code == 200:
                username = whoami_response.json().get('username', '')
                if username:
                    # Check user's packages to see what this token can access
                    packages_response = self.session.get(
                        f"{self.npm_registry_url}/-/user/{username}/package",
                        headers=headers,
                        timeout=10
                    )
                    
                    if packages_response.status_code == 200:
                        permissions['publish'] = True  # If we can list packages, we likely have publish access
                        
        except Exception as e:
            self.log(f"NPM permission check error: {str(e)}", "WARN")
        
        return permissions

    def get_npm_user_info(self, token: str) -> Dict:
        """Get NPM user information"""
        try:
            clean_token = token.strip()
            headers = {'Authorization': f'Bearer {clean_token}'}
            
            # Get user info from whoami
            response = self.session.get(
                f"{self.npm_registry_url}/-/whoami",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                whoami_data = response.json()
                username = whoami_data.get('username', '')
                
                user_info = {'username': username}
                
                # Try multiple endpoints to get user profile information
                profile_endpoints = [
                    f"{self.npm_registry_url}/-/user/org.couchdb.user:{username}",
                    f"{self.npm_registry_url}/-/npm/v1/user",
                    f"{self.npm_registry_url}/-/user/{username}"
                ]
                
                for endpoint in profile_endpoints:
                    try:
                        profile_response = self.session.get(
                            endpoint,
                            headers=headers,
                            timeout=10
                        )
                        
                        if profile_response.status_code == 200:
                            profile_data = profile_response.json()
                            if isinstance(profile_data, dict):
                                # Extract available information
                                user_info.update({
                                    'email': profile_data.get('email', user_info.get('email', '')),
                                    'name': profile_data.get('name', profile_data.get('fullname', user_info.get('name', ''))),
                                    'type': profile_data.get('type', user_info.get('type', 'user')),
                                    'created': profile_data.get('created', user_info.get('created', '')),
                                    'updated': profile_data.get('updated', user_info.get('updated', '')),
                                    'homepage': profile_data.get('homepage', user_info.get('homepage', '')),
                                    'github': profile_data.get('github', user_info.get('github', '')),
                                    'twitter': profile_data.get('twitter', user_info.get('twitter', ''))
                                })
                                
                                # If we found email, we can break
                                if user_info.get('email'):
                                    break
                                    
                    except Exception:
                        continue
                
                # Try to get user profile from the public API if we still don't have email
                if not user_info.get('email'):
                    try:
                        public_profile_response = self.session.get(
                            f"{self.npm_registry_url}/-/user/{username}",
                            timeout=10
                        )
                        
                        if public_profile_response.status_code == 200:
                            public_data = public_profile_response.json()
                            if isinstance(public_data, dict):
                                user_info.update({
                                    'email': public_data.get('email', user_info.get('email', '')),
                                    'name': public_data.get('name', user_info.get('name', '')),
                                    'homepage': public_data.get('homepage', user_info.get('homepage', '')),
                                    'github': public_data.get('github', user_info.get('github', '')),
                                    'twitter': public_data.get('twitter', user_info.get('twitter', ''))
                                })
                    except Exception:
                        pass
                
                # Try to get email from npm profile endpoint
                if not user_info.get('email'):
                    try:
                        profile_response = self.session.get(
                            f"{self.npm_registry_url}/-/npm/v1/user",
                            headers=headers,
                            timeout=10
                        )
                        
                        if profile_response.status_code == 200:
                            profile_data = profile_response.json()
                            if isinstance(profile_data, dict):
                                user_info.update({
                                    'email': profile_data.get('email', user_info.get('email', '')),
                                    'name': profile_data.get('name', user_info.get('name', '')),
                                    'avatarURL': profile_data.get('avatarURL', user_info.get('avatarURL', '')),
                                    'created': profile_data.get('created', user_info.get('created', '')),
                                    'updated': profile_data.get('updated', user_info.get('updated', ''))
                                })
                    except Exception:
                        pass
                
                return user_info
            
            return {}
            
        except Exception as e:
            self.log(f"Error getting NPM user info: {str(e)}", "ERROR")
            return {}

    def get_comprehensive_npm_user_info(self, token: str) -> Dict:
        """Get comprehensive NPM user information including statistics and security details"""
        user_info = {}  # Initialize with empty dict to avoid UnboundLocalError
        
        try:
            clean_token = token.strip()
            headers = {'Authorization': f'Bearer {clean_token}'}
            
            # Get basic user info first
            user_info = self.get_npm_user_info(token)
            username = user_info.get('username', '')
            
            if not username:
                return user_info
            
            # Enhance with additional information
            enhanced_info = user_info.copy()
            
            # Get user's download statistics
            try:
                stats_response = self.session.get(
                    f"{self.npm_registry_url}/-/user/{username}/downloads",
                    headers=headers,
                    timeout=10
                )
                
                if stats_response.status_code == 200:
                    stats_data = stats_response.json()
                    enhanced_info['download_stats'] = stats_data
            except Exception:
                pass
            
            # Get user's publishing activity
            try:
                activity_response = self.session.get(
                    f"{self.npm_registry_url}/-/user/{username}/activity",
                    headers=headers,
                    timeout=10
                )
                
                if activity_response.status_code == 200:
                    activity_data = activity_response.json()
                    enhanced_info['recent_activity'] = activity_data
            except Exception:
                pass
            
            # Get security/2FA status
            try:
                security_response = self.session.get(
                    f"{self.npm_registry_url}/-/npm/v1/user",
                    headers=headers,
                    timeout=10
                )
                
                if security_response.status_code == 200:
                    security_data = security_response.json()
                    enhanced_info.update({
                        'tfa_enabled': security_data.get('tfa', {}).get('mode', 'disabled') != 'disabled',
                        'tfa_mode': security_data.get('tfa', {}).get('mode', 'disabled'),
                        'email_verified': security_data.get('emailVerified', False),
                        'created_packages': security_data.get('createdPackages', 0),
                        'maintained_packages': security_data.get('maintainedPackages', 0)
                    })
            except Exception:
                pass
            
            # Get user's stars/favorites
            try:
                stars_response = self.session.get(
                    f"{self.npm_registry_url}/-/user/{username}/starred",
                    headers=headers,
                    timeout=10
                )
                
                if stars_response.status_code == 200:
                    stars_data = stars_response.json()
                    enhanced_info['starred_packages'] = stars_data
            except Exception:
                pass
            
            # Get user's followers/following
            try:
                followers_response = self.session.get(
                    f"{self.npm_registry_url}/-/user/{username}/followers",
                    headers=headers,
                    timeout=10
                )
                
                if followers_response.status_code == 200:
                    followers_data = followers_response.json()
                    enhanced_info['followers'] = followers_data
            except Exception:
                pass
            
            # Get package statistics
            packages = self.get_npm_packages(token)
            if packages:
                total_downloads = 0
                latest_version_dates = []
                package_types = {'scoped': 0, 'unscoped': 0, 'private': 0, 'public': 0}
                
                for package in packages:
                    # Get package download stats
                    try:
                        downloads_response = self.session.get(
                            f"{self.npm_registry_url}/-/npm/v1/downloads/point/last-month/{package['name']}",
                            timeout=5
                        )
                        
                        if downloads_response.status_code == 200:
                            downloads_data = downloads_response.json()
                            total_downloads += downloads_data.get('downloads', 0)
                    except Exception:
                        pass
                    
                    # Categorize packages
                    if '/' in package['name']:
                        package_types['scoped'] += 1
                    else:
                        package_types['unscoped'] += 1
                    
                    if package.get('private'):
                        package_types['private'] += 1
                    else:
                        package_types['public'] += 1
                
                enhanced_info['package_statistics'] = {
                    'total_packages': len(packages),
                    'total_monthly_downloads': total_downloads,
                    'package_breakdown': package_types
                }
            
            return enhanced_info
            
        except Exception as e:
            self.log(f"Error getting comprehensive NPM user info: {str(e)}", "ERROR")
            return user_info  # Return the initialized empty dict

    def get_npm_packages(self, token: str) -> List[Dict]:
        """Get packages associated with the NPM token with accurate access levels"""
        packages = []
        
        try:
            clean_token = token.strip()
            headers = {'Authorization': f'Bearer {clean_token}'}
            
            # Get user info first
            user_info = self.get_npm_user_info(token)
            username = user_info.get('username', '')
            
            if not username:
                return packages
            
            # Get user's packages with detailed permissions
            response = self.session.get(
                f"{self.npm_registry_url}/-/user/{username}/package",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                for package_name, package_data in data.items():
                    # Ensure package_data is a dictionary
                    if not isinstance(package_data, dict):
                        package_data = {}
                    
                    # Get detailed package info
                    package_info = {
                        'name': package_name,
                        'access': self.determine_package_access(package_name, clean_token, headers),
                        'role': package_data.get('role', self.determine_package_role(package_name, username, clean_token, headers))
                    }
                    
                    # Try to get more detailed package information
                    try:
                        pkg_response = self.session.get(
                            f"{self.npm_registry_url}/{package_name}",
                            headers=headers,
                            timeout=5
                        )
                        
                        if pkg_response.status_code == 200:
                            pkg_data = pkg_response.json()
                            if isinstance(pkg_data, dict):
                                package_info.update({
                                    'version': pkg_data.get('dist-tags', {}).get('latest', 'unknown'),
                                    'description': pkg_data.get('description', ''),
                                    'private': pkg_data.get('private', False),
                                    'scope': pkg_data.get('name', '').split('/')[0] if '/' in pkg_data.get('name', '') else None
                                })
                                
                                # Enhanced access determination based on package metadata
                                if package_info['access'] == 'unknown':
                                    package_info['access'] = self.determine_access_from_metadata(
                                        pkg_data, username, clean_token, headers
                                    )
                    except Exception:
                        pass
                    
                    packages.append(package_info)
            
            # Also try to get packages from any organizations/scopes the user has access to
            try:
                # Try to get organization memberships
                orgs_response = self.session.get(
                    f"{self.npm_registry_url}/-/user/{username}/orgs",
                    headers=headers,
                    timeout=10
                )
                
                if orgs_response.status_code == 200:
                    orgs_data = orgs_response.json()
                    if isinstance(orgs_data, dict):
                        for org_name, org_info in orgs_data.items():
                            # Ensure org_info is a dictionary
                            if not isinstance(org_info, dict):
                                org_info = {}
                            
                            # Try to get packages from this organization
                            try:
                                org_packages_response = self.session.get(
                                    f"{self.npm_registry_url}/-/user/{org_name}/package",
                                    headers=headers,
                                    timeout=10
                                )
                                
                                if org_packages_response.status_code == 200:
                                    org_packages = org_packages_response.json()
                                    if isinstance(org_packages, dict):
                                        for pkg_name, pkg_info in org_packages.items():
                                            # Ensure pkg_info is a dictionary
                                            if not isinstance(pkg_info, dict):
                                                pkg_info = {}
                                            
                                            # Add organization packages with scope info
                                            packages.append({
                                                'name': pkg_name,
                                                'access': self.determine_package_access(pkg_name, clean_token, headers),
                                                'role': pkg_info.get('role', self.determine_org_package_role(
                                                    pkg_name, org_name, username, clean_token, headers
                                                )),
                                                'scope': org_name,
                                                'organization': True
                                            })
                            except Exception:
                                continue
                            
            except Exception:
                pass
                    
        except Exception as e:
            self.log(f"Error getting NPM packages: {str(e)}", "ERROR")
        
        return packages

    def determine_package_access(self, package_name: str, token: str, headers: Dict) -> str:
        """Determine the access level the token has to a specific package"""
        try:
            # Test different operations to determine access level
            
            # 1. Try to get package details (read access test)
            pkg_response = self.session.get(
                f"{self.npm_registry_url}/{package_name}",
                headers=headers,
                timeout=5
            )
            
            if pkg_response.status_code == 404:
                return 'not_found'
            elif pkg_response.status_code == 403:
                return 'denied'
            elif pkg_response.status_code != 200:
                return 'unknown'
            
            pkg_data = pkg_response.json()
            if not isinstance(pkg_data, dict):
                return 'unknown'
            
            # 2. Check if we can access package access info (indicates higher permissions)
            try:
                access_response = self.session.get(
                    f"{self.npm_registry_url}/-/package/{package_name}/access",
                    headers=headers,
                    timeout=5
                )
                
                if access_response.status_code == 200:
                    access_data = access_response.json()
                    if isinstance(access_data, dict):
                        # If we can see access info, we likely have admin or write access
                        return 'admin'  # Can manage package access
                elif access_response.status_code == 403:
                    # We can read the package but not manage access
                    pass
            except Exception:
                pass
            
            # 3. Try to check package collaborators (write/admin access indicator)
            try:
                collab_response = self.session.get(
                    f"{self.npm_registry_url}/-/package/{package_name}/collaborators",
                    headers=headers,
                    timeout=5
                )
                
                if collab_response.status_code == 200:
                    # If we can see collaborators, we have at least write access
                    collab_data = collab_response.json()
                    if isinstance(collab_data, dict):
                        # Check our own permissions in the collaborators list
                        user_info = self.get_npm_user_info(token)
                        username = user_info.get('username', '')
                        
                        if username and username in collab_data:
                            user_perms = collab_data.get(username, 'read')
                            if user_perms == 'write':
                                return 'write'
                            elif user_perms == 'admin':
                                return 'admin'
                        
                        # If we can see the list but our permissions aren't clear
                        return 'write'
                elif collab_response.status_code == 403:
                    # Can't see collaborators, likely read-only
                    pass
            except Exception:
                pass
            
            # 4. Check if package is private (affects access interpretation)
            is_private = pkg_data.get('private', False)
            
            # 5. Try to get download stats (usually available for packages we can read)
            try:
                stats_response = self.session.get(
                    f"{self.npm_registry_url}/-/npm/v1/downloads/point/last-week/{package_name}",
                    headers=headers,
                    timeout=5
                )
                
                if stats_response.status_code == 200:
                    # We have read access at minimum
                    read_access = True
                else:
                    read_access = False
            except Exception:
                read_access = True  # Assume we have read access if we got the package data
            
            # 6. Determine access level based on what we've learned
            if is_private:
                # For private packages, if we can read it, we likely have explicit access
                return 'read'  # At minimum read access to private package
            else:
                # For public packages, try to determine if we have write access
                # Check if we're in the maintainers list
                maintainers = pkg_data.get('maintainers', [])
                if maintainers:
                    user_info = self.get_npm_user_info(token)
                    username = user_info.get('username', '')
                    
                    for maintainer in maintainers:
                        if isinstance(maintainer, dict) and maintainer.get('name') == username:
                            return 'write'  # We're a maintainer
                        elif isinstance(maintainer, str) and maintainer == username:
                            return 'write'  # We're a maintainer
                
                # If we can read but aren't a maintainer, it's likely public read access
                return 'read'
                
        except Exception as e:
            self.log(f"Error determining access for {package_name}: {str(e)}", "WARN")
            return 'unknown'

    def determine_package_role(self, package_name: str, username: str, token: str, headers: Dict) -> str:
        """Determine the user's role for a specific package"""
        try:
            # Get package details
            pkg_response = self.session.get(
                f"{self.npm_registry_url}/{package_name}",
                headers=headers,
                timeout=5
            )
            
            if pkg_response.status_code == 200:
                pkg_data = pkg_response.json()
                if isinstance(pkg_data, dict):
                    # Check if user is the owner
                    author = pkg_data.get('author', {})
                    if isinstance(author, dict) and author.get('name') == username:
                        return 'owner'
                    elif isinstance(author, str) and author == username:
                        return 'owner'
                    
                    # Check if user is in maintainers
                    maintainers = pkg_data.get('maintainers', [])
                    for maintainer in maintainers:
                        if isinstance(maintainer, dict) and maintainer.get('name') == username:
                            return 'maintainer'
                        elif isinstance(maintainer, str) and maintainer == username:
                            return 'maintainer'
                    
                    # Check if user is in contributors
                    contributors = pkg_data.get('contributors', [])
                    for contributor in contributors:
                        if isinstance(contributor, dict) and contributor.get('name') == username:
                            return 'contributor'
                        elif isinstance(contributor, str) and contributor == username:
                            return 'contributor'
                    
                    # If we can access the package but aren't in the above lists
                    if pkg_data.get('private', False):
                        return 'collaborator'  # Has access to private package
                    else:
                        return 'viewer'  # Can read public package
            
            return 'unknown'
            
        except Exception:
            return 'unknown'

    def determine_org_package_role(self, package_name: str, org_name: str, username: str, token: str, headers: Dict) -> str:
        """Determine the user's role for an organization package"""
        try:
            # First check the package-level role
            package_role = self.determine_package_role(package_name, username, token, headers)
            if package_role != 'unknown':
                return f'org_{package_role}'
            
            # If package role is unknown, check org membership role
            orgs_response = self.session.get(
                f"{self.npm_registry_url}/-/user/{username}/orgs",
                headers=headers,
                timeout=5
            )
            
            if orgs_response.status_code == 200:
                orgs_data = orgs_response.json()
                if isinstance(orgs_data, dict) and org_name in orgs_data:
                    org_info = orgs_data[org_name]
                    if isinstance(org_info, dict):
                        org_role = org_info.get('role', 'member')
                        return f'org_{org_role}'
            
            return 'org_member'
            
        except Exception:
            return 'unknown'

    def determine_access_from_metadata(self, pkg_data: Dict, username: str, token: str, headers: Dict) -> str:
        """Determine access level from package metadata"""
        try:
            # Check if user is in maintainers (write access)
            maintainers = pkg_data.get('maintainers', [])
            for maintainer in maintainers:
                maintainer_name = maintainer.get('name') if isinstance(maintainer, dict) else maintainer
                if maintainer_name == username:
                    return 'write'
            
            # Check if user is the author (admin access)
            author = pkg_data.get('author', {})
            author_name = author.get('name') if isinstance(author, dict) else author
            if author_name == username:
                return 'admin'
            
            # Check if it's a private package (if we can read it, we have explicit access)
            if pkg_data.get('private', False):
                return 'read'
            
            # For public packages, default to read access
            return 'read'
            
        except Exception:
            return 'unknown'

    def format_access_display(self, access: str, role: str) -> str:
        """Format access and role information for display"""
        access_emojis = {
            'admin': '👑',
            'write': '✏️',
            'read': '👁️',
            'denied': '🚫',
            'not_found': '❓',
            'unknown': '❓'
        }
        
        role_descriptions = {
            'owner': 'Package Owner',
            'maintainer': 'Maintainer',
            'contributor': 'Contributor',
            'collaborator': 'Collaborator',
            'viewer': 'Viewer',
            'org_owner': 'Org Owner',
            'org_maintainer': 'Org Maintainer', 
            'org_member': 'Org Member',
            'unknown': 'Unknown Role'
        }
        
        access_desc = access.replace('_', ' ').title()
        role_desc = role_descriptions.get(role, role.replace('_', ' ').title())
        emoji = access_emojis.get(access, '❓')
        
        return f"{emoji} {access_desc} ({role_desc})"

    def get_npm_token_details(self, token: str) -> Dict:
        """Get detailed NPM token information including scopes and permissions"""
        token_details = {
            'scopes': [],
            'packages': [],
            'organizations': [],
            'token_info': {}
        }
        
        try:
            clean_token = token.strip()
            headers = {'Authorization': f'Bearer {clean_token}'}
            
            # Get token information
            tokens_response = self.session.get(
                f"{self.npm_registry_url}/-/npm/v1/tokens",
                headers=headers,
                timeout=10
            )
            
            if tokens_response.status_code == 200:
                tokens_data = tokens_response.json()
                # Find current token in the list
                for token_info in tokens_data.get('objects', []):
                    token_key = token_info.get('key', '')
                    # Try to match the token (NPM tokens are usually identified by their key)
                    if len(token_key) > 8 and token.endswith(token_key[-8:]):
                        token_details['token_info'] = {
                            'key': token_key,
                            'readonly': token_info.get('readonly', False),
                            'automation': token_info.get('automation', False),
                            'cidr_whitelist': token_info.get('cidr_whitelist', []),
                            'created': token_info.get('created', ''),
                            'updated': token_info.get('updated', ''),
                            'token': token_info.get('token', '')
                        }
                        break
            
            # Get user info to find username
            user_info = self.get_npm_user_info(token)
            username = user_info.get('username', '')
            
            if username:
                # Get user's organizations and scopes
                try:
                    orgs_response = self.session.get(
                        f"{self.npm_registry_url}/-/user/{username}/orgs",
                        headers=headers,
                        timeout=10
                    )
                    
                    if orgs_response.status_code == 200:
                        orgs_data = orgs_response.json()
                        for org_name, org_info in orgs_data.items():
                            token_details['organizations'].append({
                                'name': org_name,
                                'role': org_info.get('role', 'unknown'),
                                'scope': f"@{org_name}"
                            })
                            token_details['scopes'].append(f"@{org_name}")
                            
                except Exception as e:
                    self.log(f"Error getting organizations: {str(e)}", "WARN")
                
                # Get package access for this token
                packages = self.get_npm_packages(token)
                token_details['packages'] = packages
                
                # Extract unique scopes from packages
                for package in packages:
                    if package.get('scope'):
                        scope = package['scope']
                        if scope not in token_details['scopes']:
                            token_details['scopes'].append(scope)
                    elif '/' in package['name']:
                        # Extract scope from scoped package name
                        scope = package['name'].split('/')[0]
                        if scope not in token_details['scopes']:
                            token_details['scopes'].append(scope)
                            
        except Exception as e:
            self.log(f"Error getting NPM token details: {str(e)}", "ERROR")
        
        return token_details

    def generate_npm_json_output(self, token: str) -> Dict:
        """Generate JSON output for NPM token analysis"""
        output = {
            "token_valid": False,
            "user_info": {},
            "token_details": {},
            "permissions": {},
            "scopes": [],
            "organizations": [],
            "packages": {
                "total": 0,
                "scoped": [],
                "unscoped": [],
                "by_scope": {}
            },
            "statistics": {
                "total_packages": 0,
                "monthly_downloads": 0,
                "scoped_count": 0,
                "unscoped_count": 0,
                "private_count": 0,
                "public_count": 0
            }
        }
        
        # Check token validity
        is_valid, validation_info = self.validate_npm_token(token)
        if not is_valid:
            output["error"] = validation_info.get('error', 'Invalid token')
            return output
        
        output["token_valid"] = True
        output["permissions"] = validation_info.get('permissions', {})
        
        # Get comprehensive user info
        user_info = self.get_comprehensive_npm_user_info(token)
        if user_info:
            output["user_info"] = {
                "username": user_info.get('username', ''),
                "name": user_info.get('name', ''),
                "email": user_info.get('email', ''),
                "type": user_info.get('type', 'user'),
                "created": user_info.get('created', ''),
                "homepage": user_info.get('homepage', ''),
                "github": user_info.get('github', ''),
                "twitter": user_info.get('twitter', ''),
                "tfa_enabled": user_info.get('tfa_enabled', False),
                "tfa_mode": user_info.get('tfa_mode', 'disabled'),
                "email_verified": user_info.get('email_verified', False),
                "starred_packages": user_info.get('starred_packages', []),
                "followers": user_info.get('followers', [])
            }
            
            # Package statistics
            if user_info.get('package_statistics'):
                stats = user_info['package_statistics']
                output["statistics"] = {
                    "total_packages": stats.get('total_packages', 0),
                    "monthly_downloads": stats.get('total_monthly_downloads', 0),
                    "scoped_count": stats.get('package_breakdown', {}).get('scoped', 0),
                    "unscoped_count": stats.get('package_breakdown', {}).get('unscoped', 0),
                    "private_count": stats.get('package_breakdown', {}).get('private', 0),
                    "public_count": stats.get('package_breakdown', {}).get('public', 0)
                }
        
        # Get token details
        token_details = self.get_npm_token_details(token)
        if token_details:
            output["token_details"] = token_details.get('token_info', {})
            output["scopes"] = token_details.get('scopes', [])
            output["organizations"] = token_details.get('organizations', [])
            
            # Process packages
            packages = token_details.get('packages', [])
            output["packages"]["total"] = len(packages)
            
            scoped_packages = []
            unscoped_packages = []
            by_scope = {}
            
            for package in packages:
                package_data = {
                    "name": package['name'],
                    "version": package.get('version', ''),
                    "description": package.get('description', ''),
                    "role": package.get('role', 'unknown'),
                    "access": package.get('access', 'unknown'),
                    "private": package.get('private', False),
                    "scope": package.get('scope', ''),
                    "organization": package.get('organization', False)
                }
                
                if package.get('scope') or '/' in package['name']:
                    scoped_packages.append(package_data)
                    scope = package.get('scope', package['name'].split('/')[0])
                    if scope not in by_scope:
                        by_scope[scope] = []
                    by_scope[scope].append(package_data)
                else:
                    unscoped_packages.append(package_data)
            
            output["packages"]["scoped"] = scoped_packages
            output["packages"]["unscoped"] = unscoped_packages
            output["packages"]["by_scope"] = by_scope
        
        return output


# GitHub PAT Checker class - keeping the existing implementation
class GitHubPATChecker:
    """GitHub PAT functionality - fully restored"""
    
    def __init__(self, token: str, ghe: str):
        self.token = token

        # If GitHub Enterprise, use custom URL
        if ghe:
            self.base_url = f"https://{ghe}"
            self.route = f"/api/v3"
        else:
            self.base_url = "https://api.github.com"
            self.route = ""

        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Detect if this is a fine-grained PAT
        self.is_fine_grained = self.token.startswith('github_pat_')
        
        # Flag to suppress warnings during JSON output
        self.json_mode = False
        
        if self.is_fine_grained:
            # Fine-grained PATs use different headers
            self.headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            self.session.headers.update(self.headers)

    def check_token_validity(self) -> bool:
        """Check if the token is valid by making a simple API call."""
        try:
            response = self.session.get(f"{self.base_url + self.route}/user")
            return response.status_code == 200
        except requests.RequestException:
            return False

    def get_token_scopes(self) -> List[str]:
        """Get the scopes/permissions of the PAT."""
        try:
            response = self.session.get(f"{self.base_url + self.route}/user")
            if response.status_code == 200:
                # GitHub returns scopes in the X-OAuth-Scopes header
                scopes_header = response.headers.get('X-OAuth-Scopes', '')
                if scopes_header:
                    return [scope.strip() for scope in scopes_header.split(',')]
                else:
                    return []
            else:
                return []
        except requests.RequestException:
            return []

    def get_rate_limit_info(self) -> Dict:
        """Get rate limit information for the token."""
        try:
            response = self.session.get(f"{self.base_url + self.route}/rate_limit")
            if response.status_code == 200:
                return response.json()
            else:
                return {}
        except requests.RequestException:
            return {}

    def get_user_info(self) -> Dict:
        """Get information about the authenticated user."""
        try:
            response = self.session.get(f"{self.base_url + self.route}/user")
            if response.status_code == 200:
                return response.json()
            else:
                return {}
        except requests.RequestException:
            return {}

    def get_accessible_repositories(self) -> List[Dict]:
        """Get all repositories accessible to the PAT."""
        repositories = []
        page = 1
        per_page = 100

        while True:
            try:
                response = self.session.get(
                    f"{self.base_url + self.route}/user/repos",
                    params={
                        "per_page": per_page,
                        "page": page,
                        "sort": "updated",
                        "direction": "desc"
                    }
                )
                
                if response.status_code == 200:
                    repos = response.json()
                    if not repos:
                        break
                    
                    for repo in repos:
                        repositories.append({
                            "name": repo["full_name"],
                            "private": repo["private"],
                            "owner": repo["owner"]["login"],
                            "permissions": repo.get("permissions", {}),
                            "url": repo["html_url"]
                        })
                    
                    page += 1
                else:
                    break
                    
            except requests.RequestException:
                break

        return repositories

    def get_user_organizations(self, suppress_warnings: bool = False) -> List[Dict]:
        """Get organizations the authenticated user is a member of."""
        organizations = []
        page = 1
        per_page = 100

        while True:
            try:
                response = self.session.get(
                    f"{self.base_url + self.route}/user/orgs",
                    params={"per_page": per_page, "page": page}
                )
                
                if response.status_code == 200:
                    orgs = response.json()
                    if not orgs:
                        break
                    
                    for org in orgs:
                        # Get user's login for role checking
                        user_login = self.get_user_info().get('login', '')
                        
                        # Get detailed organization information
                        org_login = org.get("login", "")
                        org_details = self.get_organization_details(org_login)
                        
                        organizations.append({
                            "login": org_login,
                            "id": org.get("id", 0),
                            "name": org_details.get("name", org.get("name", "")),
                            "description": org_details.get("description", org.get("description", "")),
                            "public_repos": org_details.get("public_repos", 0),
                            "private_repos": org_details.get("total_private_repos", 0),
                            "url": org.get("html_url", f"{self.base_url}/{org_login}"),
                            "role": self.get_user_role_in_org(org_login, user_login)
                        })
                    
                    page += 1
                elif response.status_code == 403:
                    # Token might not have org scope
                    if not suppress_warnings:
                        print("   ⚠️  Unable to access organization information (insufficient permissions)")
                    break
                else:
                    break
                    
            except requests.RequestException as e:
                if not suppress_warnings:
                    print(f"   ❌ Error getting organizations: {e}")
                break

        return organizations

    def get_organization_details(self, org_login: str) -> Dict:
        """Get detailed information about an organization."""
        try:
            response = self.session.get(f"{self.base_url + self.route}/orgs/{org_login}")
            
            if response.status_code == 200:
                return response.json()
            else:
                return {}
                
        except requests.RequestException:
            return {}

    def get_user_role_in_org(self, org_login: str, user_login: str) -> str:
        """Get the user's role in a specific organization."""
        if not org_login or not user_login:
            return "unknown"
            
        try:
            # First try to get membership info
            response = self.session.get(f"{self.base_url + self.route}/orgs/{org_login}/memberships/{user_login}")
            
            if response.status_code == 200:
                membership = response.json()
                return membership.get("role", "member")
            elif response.status_code == 403:
                # Insufficient permissions to see detailed membership
                return "member"
            else:
                # Try alternative method - check if user can access org details
                org_response = self.session.get(f"{self.base_url + self.route}/orgs/{org_login}")
                if org_response.status_code == 200:
                    org_data = org_response.json()
                    # If we can see private info, we might be an admin
                    if org_data.get("billing_email") or org_data.get("plan"):
                        return "admin"
                
                return "member"
                
        except requests.RequestException:
            return "member"

    def get_organization_repositories(self, org_name: str) -> List[Dict]:
        """Get repositories accessible in a specific organization."""
        repositories = []
        page = 1
        per_page = 100

        while True:
            try:
                response = self.session.get(
                    f"{self.base_url + self.route}/orgs/{org_name}/repos",
                    params={
                        "per_page": per_page,
                        "page": page,
                        "sort": "updated",
                        "direction": "desc"
                    }
                )
                
                if response.status_code == 200:
                    repos = response.json()
                    if not repos:
                        break
                    
                    for repo in repos:
                        repositories.append({
                            "name": repo["full_name"],
                            "private": repo["private"],
                            "owner": repo["owner"]["login"],
                            "permissions": repo.get("permissions", {}),
                            "url": repo["html_url"]
                        })
                    
                    page += 1
                elif response.status_code == 404:
                    print(f"Organization '{org_name}' not found or not accessible")
                    break
                else:
                    print(f"Error getting organization repositories: {response.status_code}")
                    break
                    
            except requests.RequestException as e:
                print(f"Error making request: {e}")
                break

        return repositories

    def print_scope_descriptions(self, scopes: List[str]):
        """Print descriptions of what each scope allows."""
        scope_descriptions = {
            "repo": "Full access to repositories",
            "repo:status": "Access to commit status",
            "repo_deployment": "Access to deployment statuses",
            "public_repo": "Access to public repositories",
            "repo:invite": "Access to repository invitations",
            "security_events": "Access to security events",
            "admin:repo_hook": "Full access to repository hooks",
            "write:repo_hook": "Write access to repository hooks",
            "read:repo_hook": "Read access to repository hooks",
            "admin:org": "Full access to organization, teams, and memberships",
            "write:org": "Write access to organization and teams",
            "read:org": "Read access to organization and teams",
            "admin:public_key": "Full access to public keys",
            "write:public_key": "Write access to public keys",
            "read:public_key": "Read access to public keys",
            "admin:org_hook": "Full access to organization hooks",
            "gist": "Write access to gists",
            "notifications": "Access to notifications",
            "user": "Access to user profile information",
            "user:email": "Access to user email addresses",
            "user:follow": "Access to follow/unfollow users",
            "delete_repo": "Delete access to repositories",
            "write:discussion": "Write access to team discussions",
            "read:discussion": "Read access to team discussions",
            "write:packages": "Write access to GitHub packages",
            "read:packages": "Read access to GitHub packages",
            "delete:packages": "Delete access to GitHub packages",
            "admin:gpg_key": "Full access to GPG keys",
            "write:gpg_key": "Write access to GPG keys",
            "read:gpg_key": "Read access to GPG keys",
            "workflow": "Access to GitHub Actions workflows"
        }
        
        print("\nScope Descriptions:")
        print("-" * 50)
        for scope in scopes:
            description = scope_descriptions.get(scope, "Unknown scope")
            print(f"  {scope}: {description}")

    def download_repository(self, repo_name: str, repo_url: str, base_path: str = "repos") -> bool:
        """Download a single repository using git clone."""
        try:
            # Create base directory if it doesn't exist
            os.makedirs(base_path, exist_ok=True)
            
            # Create owner directory
            owner = repo_name.split('/')[0]
            owner_path = os.path.join(base_path, owner)
            os.makedirs(owner_path, exist_ok=True)
            
            # Clone the repository
            clone_path = os.path.join(owner_path, repo_name.split('/')[1])
            
            # Skip if already exists
            if os.path.exists(clone_path):
                print(f"      ⚠️  {repo_name} already exists, skipping...")
                return True
            
            # Construct authenticated clone URL
            auth_url = repo_url.replace('https://', f'https://{self.token}@')
            
            print(f"      📥 Downloading {repo_name}...")
            result = subprocess.run([
                'git', 'clone', auth_url, clone_path
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"      ✅ Successfully downloaded {repo_name}")
                return True
            else:
                print(f"      ❌ Failed to download {repo_name}: {result.stderr.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"      ⏱️  Timeout downloading {repo_name}")
            return False
        except Exception as e:
            print(f"      ❌ Error downloading {repo_name}: {str(e)}")
            return False

    def download_all_repositories(self, org_name: Optional[str] = None, base_path: str = "repos", 
                                 repo_type: str = "all") -> Dict[str, int]:
        """Download all accessible repositories."""
        print(f"\n📦 Repository Download Manager")
        print("=" * 50)
        
        # Get repositories
        repositories = self.get_accessible_repositories()
        if org_name:
            org_repos = self.get_organization_repositories(org_name)
            repositories.extend(org_repos)
        
        if not repositories:
            print("❌ No repositories found to download")
            return {"total": 0, "success": 0, "failed": 0, "skipped": 0}
        
        # Filter repositories based on type
        if repo_type == "private":
            repositories = [repo for repo in repositories if repo['private']]
        elif repo_type == "public":
            repositories = [repo for repo in repositories if not repo['private']]
        
        # Separate by type for reporting
        private_repos = [repo for repo in repositories if repo['private']]
        public_repos = [repo for repo in repositories if not repo['private']]
        
        print(f"📊 Download Summary:")
        print(f"   Total repositories to download: {len(repositories)}")
        print(f"   • Private: {len(private_repos)}")
        print(f"   • Public: {len(public_repos)}")
        print(f"   Download path: {os.path.abspath(base_path)}")
        
        # Check if git is available
        try:
            subprocess.run(['git', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Git is not installed or not available in PATH")
            print("   Please install git to download repositories")
            return {"total": 0, "success": 0, "failed": 0, "skipped": 0}
        
        # Download repositories
        stats = {"total": len(repositories), "success": 0, "failed": 0, "skipped": 0}
        
        if private_repos:
            print(f"\n🔒 Downloading Private Repositories ({len(private_repos)}):")
            for repo in private_repos:
                if os.path.exists(os.path.join(base_path, repo['owner'], repo['name'].split('/')[1])):
                    stats["skipped"] += 1
                elif self.download_repository(repo['name'], repo['url'], base_path):
                    stats["success"] += 1
                else:
                    stats["failed"] += 1
        
        if public_repos:
            print(f"\n🔓 Downloading Public Repositories ({len(public_repos)}):")
            for repo in public_repos:
                if os.path.exists(os.path.join(base_path, repo['owner'], repo['name'].split('/')[1])):
                    stats["skipped"] += 1
                elif self.download_repository(repo['name'], repo['url'], base_path):
                    stats["success"] += 1
                else:
                    stats["failed"] += 1
        
        # Final summary
        print(f"\n📈 Download Complete!")
        print(f"   ✅ Successful: {stats['success']}")
        print(f"   ❌ Failed: {stats['failed']}")
        print(f"   ⚠️  Skipped (already exists): {stats['skipped']}")
        print(f"   📁 Downloaded to: {os.path.abspath(base_path)}")
        
        return stats

    def enumerate_variables(self, target_type: str = "all", target_name: Optional[str] = None) -> Dict:
        """Enumerate GitHub variables at different scopes"""
        variables_info = {
            "user_variables": [],
            "repository_variables": {},
            "organization_variables": {},
            "summary": {
                "total_user_variables": 0,
                "total_repo_variables": 0,
                "total_org_variables": 0,
                "accessible_repos": 0,
                "accessible_orgs": 0
            }
        }
        
        print(f"\n🔍 GitHub Variables Enumeration")
        print("=" * 50)
        
        # Get user variables if requested
        if target_type in ["all", "user"]:
            print("📋 Enumerating user variables...")
            user_vars = self.get_user_variables()
            variables_info["user_variables"] = user_vars
            variables_info["summary"]["total_user_variables"] = len(user_vars)
            
            if user_vars:
                print(f"   ✅ Found {len(user_vars)} user variables")
                self.display_variables(user_vars, "User")
            else:
                print("   ❌ No user variables found or accessible")
        
        # Get repository variables if requested
        if target_type in ["all", "repo", "repository"]:
            print("\n📦 Enumerating repository variables...")
            
            # If specific repository is requested
            if target_name and target_type in ["repo", "repository"]:
                repo_vars = self.get_repository_variables(target_name)
                variables_info["repository_variables"][target_name] = repo_vars
                variables_info["summary"]["total_repo_variables"] += len(repo_vars)
                variables_info["summary"]["accessible_repos"] = 1
                
                if repo_vars:
                    print(f"   ✅ Found {len(repo_vars)} variables in {target_name}")
                    self.display_variables(repo_vars, f"Repository ({target_name})")
                else:
                    print(f"   ❌ No variables found in repository {target_name}")
            else:
                # Get all accessible repositories
                repositories = self.get_accessible_repositories()
                variables_info["summary"]["accessible_repos"] = len(repositories)
                
                print(f"   Scanning {len(repositories)} accessible repositories...")
                
                for i, repo in enumerate(repositories):
                    repo_name = repo['name']
                    print(f"      📁 Scanning {repo_name} ({i+1}/{len(repositories)})...")
                    repo_vars = self.get_repository_variables(repo_name)
                    
                    if repo_vars:
                        variables_info["repository_variables"][repo_name] = repo_vars
                        variables_info["summary"]["total_repo_variables"] += len(repo_vars)
                        print(f"      ✅ {repo_name}: {len(repo_vars)} variables")
                        self.display_variables(repo_vars, f"Repository ({repo_name})", indent="        ")
                    else:
                        print(f"      ❌ {repo_name}: No variables found")
                
                print(f"   📊 Completed scan of all {len(repositories)} repositories")
        
        # Get organization variables if requested
        if target_type in ["all", "org", "organization"]:
            print("\n🏢 Enumerating organization variables...")
            
            # If specific organization is requested
            if target_name and target_type in ["org", "organization"]:
                org_vars = self.get_organization_variables(target_name)
                variables_info["organization_variables"][target_name] = org_vars
                variables_info["summary"]["total_org_variables"] += len(org_vars)
                variables_info["summary"]["accessible_orgs"] = 1
                
                if org_vars:
                    print(f"   ✅ Found {len(org_vars)} variables in {target_name}")
                    self.display_variables(org_vars, f"Organization ({target_name})")
                else:
                    print(f"   ❌ No variables found in organization {target_name}")
            else:
                # Get all accessible organizations
                organizations = self.get_user_organizations(suppress_warnings=True)
                variables_info["summary"]["accessible_orgs"] = len(organizations)
                
                if organizations:
                    print(f"   Scanning {len(organizations)} accessible organizations...")
                    
                    for org in organizations:
                        org_name = org['login']
                        org_vars = self.get_organization_variables(org_name)
                        
                        if org_vars:
                            variables_info["organization_variables"][org_name] = org_vars
                            variables_info["summary"]["total_org_variables"] += len(org_vars)
                            print(f"      ✅ {org_name}: {len(org_vars)} variables")
                            self.display_variables(org_vars, f"Organization ({org_name})", indent="        ")
                else:
                    print("   ❌ No organizations found or accessible")
        
        # Print summary
        print(f"\n📊 Variables Summary:")
        print(f"   • User variables: {variables_info['summary']['total_user_variables']}")
        print(f"   • Repository variables: {variables_info['summary']['total_repo_variables']} (from {len(variables_info['repository_variables'])} repos)")
        print(f"   • Organization variables: {variables_info['summary']['total_org_variables']} (from {len(variables_info['organization_variables'])} orgs)")
        print(f"   • Total variables found: {variables_info['summary']['total_user_variables'] + variables_info['summary']['total_repo_variables'] + variables_info['summary']['total_org_variables']}")
        
        return variables_info

    def display_variables(self, variables: List[Dict], scope_name: str, indent: str = "      "):
        """Display variables in a formatted way with color coding"""
        if not variables:
            return
            
        print(f"\n{indent}📋 {scope_name} Variables:")
        
        # Group variables by type
        by_type = {}
        for var in variables:
            var_type = var.get('type', 'unknown')
            if var_type not in by_type:
                by_type[var_type] = []
            by_type[var_type].append(var)
        
        # Display each type
        for var_type, type_vars in by_type.items():
            type_display = var_type.replace('_', ' ').title()
            print(f"{indent}  🔑 {type_display} ({len(type_vars)} items):")
            
            for var in type_vars:
                name = var.get('name', 'Unknown')
                value = var.get('value', '')
                var_visibility = var.get('visibility', 'unknown')
                environment = var.get('environment', '')
                
                # Format value display with color coding
                if value == '[HIDDEN]':
                    value_display = "🔒 \033[92m[HIDDEN - Secret]\033[0m"  # Green color for secrets
                elif len(value) > 60:
                    value_display = f"\033[92m{value[:60]}...\033[0m"  # Green color for variables
                else:
                    value_display = f"\033[92m{value}\033[0m" if value else "\033[92m[EMPTY]\033[0m"  # Green color
                
                # Add visibility and environment info
                extra_info = []
                if var_visibility and var_visibility != 'unknown':
                    extra_info.append(f"visibility: {var_visibility}")
                if environment:
                    extra_info.append(f"env: {environment}")
                
                extra_str = f" ({', '.join(extra_info)})" if extra_info else ""
                
                # Color the variable name green as well
                print(f"{indent}    • \033[92m{name}\033[0m: {value_display}{extra_str}")
                
                # Show timestamps if available
                if var.get('created_at') or var.get('updated_at'):
                    timestamp_info = []
                    if var.get('created_at'):
                        timestamp_info.append(f"created: {var['created_at'][:10]}")
                    if var.get('updated_at'):
                        timestamp_info.append(f"updated: {var['updated_at'][:10]}")
                    
                    if timestamp_info:
                        print(f"{indent}      ⏱️  {', '.join(timestamp_info)}")

    def get_user_variables(self) -> List[Dict]:
        """Get user-level variables (codespace secrets and variables)"""
        variables = []
        
        try:
            # For fine-grained PATs, user-level variables might not be accessible
            # or require different endpoints
            if self.is_fine_grained:
                # Fine-grained PATs typically don't have access to user-level variables
                # unless specifically granted, and may use different endpoints
                return variables
            
            # Try to get user codespace secrets (if accessible)
            response = self.session.get(f"{self.base_url + self.route}/user/codespaces/secrets")
            if response.status_code == 200:
                secrets_data = response.json()
                for secret in secrets_data.get('secrets', []):
                    variables.append({
                        'name': secret.get('name', ''),
                        'type': 'codespace_secret',
                        'value': '[HIDDEN]',  # Secrets are not readable
                        'created_at': secret.get('created_at', ''),
                        'updated_at': secret.get('updated_at', ''),
                        'visibility': secret.get('visibility', 'private')
                    })
            
            # Try to get user variables (newer GitHub feature)
            response = self.session.get(f"{self.base_url + self.route}/user/variables")
            if response.status_code == 200:
                variables_data = response.json()
                for variable in variables_data.get('variables', []):
                    variables.append({
                        'name': variable.get('name', ''),
                        'type': 'user_variable',
                        'value': variable.get('value', ''),
                        'created_at': variable.get('created_at', ''),
                        'updated_at': variable.get('updated_at', ''),
                        'visibility': 'private'
                    })
                    
        except requests.RequestException as e:
            if self.is_fine_grained and not getattr(self, 'json_mode', False):
                print(f"      ⚠️  Fine-grained PAT may not have required permissions for user variables")
            pass  # User variables might not be accessible
        
        return variables

    def get_repository_variables(self, repo_name: str) -> List[Dict]:
        """Get repository-level variables and secrets"""
        variables = []
        
        try:
            # Enhanced headers for fine-grained PATs
            headers = self.headers.copy()
            if self.is_fine_grained:
                headers.update({
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                })
            
            # Add a small delay to avoid rate limiting when scanning many repositories
            import time
            time.sleep(0.1)  # 100ms delay between requests
            
            # Get repository variables
            response = self.session.get(
                f"{self.base_url + self.route}/repos/{repo_name}/actions/variables",
                headers=headers
            )
            
            if response.status_code == 200:
                variables_data = response.json()
                for variable in variables_data.get('variables', []):
                    variables.append({
                        'name': variable.get('name', ''),
                        'type': 'repository_variable',
                        'value': variable.get('value', ''),
                        'created_at': variable.get('created_at', ''),
                        'updated_at': variable.get('updated_at', ''),
                        'visibility': 'repository'
                    })
            elif response.status_code == 403:
                # Don't print permission errors for every repository to keep output clean
                pass
            elif response.status_code == 404:
                # Repository not found or variables not enabled - this is normal
                pass
            elif response.status_code == 429:
                # Rate limited - add longer delay and retry once
                if not getattr(self, 'json_mode', False):
                    print(f"        ⚠️  Rate limited accessing {repo_name}, waiting...")
                time.sleep(2)
                response = self.session.get(
                    f"{self.base_url + self.route}/repos/{repo_name}/actions/variables",
                    headers=headers
                )
                if response.status_code == 200:
                    variables_data = response.json()
                    for variable in variables_data.get('variables', []):
                        variables.append({
                            'name': variable.get('name', ''),
                            'type': 'repository_variable',
                            'value': variable.get('value', ''),
                            'created_at': variable.get('created_at', ''),
                            'updated_at': variable.get('updated_at', ''),
                            'visibility': 'repository'
                        })
            
            # Get repository secrets (names only, values are not readable)
            time.sleep(0.1)  # Small delay
            response = self.session.get(
                f"{self.base_url + self.route}/repos/{repo_name}/actions/secrets",
                headers=headers
            )
            
            if response.status_code == 200:
                secrets_data = response.json()
                for secret in secrets_data.get('secrets', []):
                    variables.append({
                        'name': secret.get('name', ''),
                        'type': 'repository_secret',
                        'value': '[HIDDEN]',  # Secrets are not readable
                        'created_at': secret.get('created_at', ''),
                        'updated_at': secret.get('updated_at', ''),
                        'visibility': 'repository'
                    })
            elif response.status_code == 429:
                # Rate limited - add longer delay and retry once
                if not getattr(self, 'json_mode', False):
                    print(f"        ⚠️  Rate limited accessing {repo_name} secrets, waiting...")
                time.sleep(2)
                response = self.session.get(
                    f"{self.base_url + self.route}/repos/{repo_name}/actions/secrets",
                    headers=headers
                )
                if response.status_code == 200:
                    secrets_data = response.json()
                    for secret in secrets_data.get('secrets', []):
                        variables.append({
                            'name': secret.get('name', ''),
                            'type': 'repository_secret',
                            'value': '[HIDDEN]',
                            'created_at': secret.get('created_at', ''),
                            'updated_at': secret.get('updated_at', ''),
                            'visibility': 'repository'
                        })
            
            # Get repository environments
            time.sleep(0.1)  # Small delay
            response = self.session.get(
                f"{self.base_url + self.route}/repos/{repo_name}/environments",
                headers=headers
            )
            
            if response.status_code == 200:
                envs_data = response.json()
                for env in envs_data.get('environments', []):
                    env_name = env.get('name', '')
                    
                    # Get environment variables
                    time.sleep(0.1)
                    env_vars_response = self.session.get(
                        f"{self.base_url + self.route}/repos/{repo_name}/environments/{env_name}/variables",
                        headers=headers
                    )
                    
                    if env_vars_response.status_code == 200:
                        env_vars_data = env_vars_response.json()
                        for variable in env_vars_data.get('variables', []):
                            variables.append({
                                'name': variable.get('name', ''),
                                'type': 'environment_variable',
                                'value': variable.get('value', ''),
                                'created_at': variable.get('created_at', ''),
                                'updated_at': variable.get('updated_at', ''),
                                'visibility': f'environment:{env_name}',
                                'environment': env_name
                            })
                    
                    # Get environment secrets
                    time.sleep(0.1)
                    env_secrets_response = self.session.get(
                        f"{self.base_url + self.route}/repos/{repo_name}/environments/{env_name}/secrets",
                        headers=headers
                    )
                    
                    if env_secrets_response.status_code == 200:
                        env_secrets_data = env_secrets_response.json()
                        for secret in env_secrets_data.get('secrets', []):
                            variables.append({
                                'name': secret.get('name', ''),
                                'type': 'environment_secret',
                                'value': '[HIDDEN]',
                                'created_at': secret.get('created_at', ''),
                                'updated_at': secret.get('updated_at', ''),
                                'visibility': f'environment:{env_name}',
                                'environment': env_name
                            })
            
            # For fine-grained PATs, also try to get repository-level configuration variables
            if self.is_fine_grained:
                # Try accessing repository configuration
                time.sleep(0.1)
                config_response = self.session.get(
                    f"{self.base_url + self.route}/repos/{repo_name}",
                    headers=headers
                )
                
                if config_response.status_code == 200:
                    repo_data = config_response.json()
                    # Check if we have admin access to see more configuration
                    if repo_data.get('permissions', {}).get('admin', False):
                        # Try to get additional repository settings that might contain variables
                        settings_endpoints = [
                            f"{self.base_url + self.route}/repos/{repo_name}/actions/permissions",
                            f"{self.base_url + self.route}/repos/{repo_name}/actions/permissions/selected-actions",
                            f"{self.base_url + self.route}/repos/{repo_name}/actions/permissions/workflow"
                        ]
                        
                        for endpoint in settings_endpoints:
                            try:
                                time.sleep(0.1)
                                settings_response = self.session.get(endpoint, headers=headers)
                                if settings_response.status_code == 200:
                                    settings_data = settings_response.json()
                                    # Look for any configuration that might contain sensitive data
                                    if isinstance(settings_data, dict):
                                        for key, value in settings_data.items():
                                            if key in ['allowed_actions', 'selected_actions_url', 'default_workflow_permissions']:
                                                variables.append({
                                                    'name': f'actions_{key}',
                                                    'type': 'repository_config',
                                                    'value': str(value),
                                                    'created_at': '',
                                                    'updated_at': '',
                                                    'visibility': 'repository'
                                                })
                            except:
                                continue
                            
        except requests.RequestException as e:
            if self.is_fine_grained and not getattr(self, 'json_mode', False):
                # Only show errors for specific issues, not general access denied
                if "403" not in str(e):
                    print(f"        ⚠️  Error accessing {repo_name}: {str(e)}")
            pass  # Repository might not be accessible or variables not available
        
        return variables

    def get_organization_variables(self, org_name: str) -> List[Dict]:
        """Get organization-level variables and secrets"""
        variables = []
        
        try:
            # Enhanced headers for fine-grained PATs
            headers = self.headers.copy()
            if self.is_fine_grained:
                headers.update({
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                })
            
            # Get organization variables
            response = self.session.get(
                f"{self.base_url + self.route}/orgs/{org_name}/actions/variables",
                headers=headers
            )
            
            if response.status_code == 200:
                variables_data = response.json()
                for variable in variables_data.get('variables', []):
                    variables.append({
                        'name': variable.get('name', ''),
                        'type': 'organization_variable',
                        'value': variable.get('value', ''),
                        'created_at': variable.get('created_at', ''),
                        'updated_at': variable.get('updated_at', ''),
                        'visibility': variable.get('visibility', 'private'),
                        'selected_repositories_url': variable.get('selected_repositories_url', '')
                    })
            elif response.status_code == 403:
                # Only print warnings if not in JSON mode
                if not getattr(self, 'json_mode', False):
                    print(f"        ⚠️  Access denied for {org_name} variables (insufficient permissions)")
            elif response.status_code == 404:
                # Only print warnings if not in JSON mode
                if not getattr(self, 'json_mode', False):
                    print(f"        ⚠️  Organization {org_name} not found or variables not accessible")
            
            # Get organization secrets (names only, values are not readable)
            response = self.session.get(
                f"{self.base_url + self.route}/orgs/{org_name}/actions/secrets",
                headers=headers
            )
            
            if response.status_code == 200:
                secrets_data = response.json()
                for secret in secrets_data.get('secrets', []):
                    variables.append({
                        'name': secret.get('name', ''),
                        'type': 'organization_secret',
                        'value': '[HIDDEN]',
                        'created_at': secret.get('created_at', ''),
                        'updated_at': secret.get('updated_at', ''),
                        'visibility': secret.get('visibility', 'private'),
                        'selected_repositories_url': secret.get('selected_repositories_url', '')
                    })
            
            # Get organization codespace secrets
            response = self.session.get(
                f"{self.base_url + self.route}/orgs/{org_name}/codespaces/secrets",
                headers=headers
            )
            
            if response.status_code == 200:
                codespace_secrets_data = response.json()
                for secret in codespace_secrets_data.get('secrets', []):
                    variables.append({
                        'name': secret.get('name', ''),
                        'type': 'organization_codespace_secret',
                        'value': '[HIDDEN]',
                        'created_at': secret.get('created_at', ''),
                        'updated_at': secret.get('updated_at', ''),
                        'visibility': secret.get('visibility', 'private'),
                        'selected_repositories_url': secret.get('selected_repositories_url', '')
                    })
            
            # For fine-grained PATs, also check organization settings if we have access
            if self.is_fine_grained:
                # Check organization permissions and settings
                org_response = self.session.get(
                    f"{self.base_url + self.route}/orgs/{org_name}",
                    headers=headers
                )
                
                if org_response.status_code == 200:
                    # Try to get organization-level settings that might contain configuration
                    settings_endpoints = [
                        f"{self.base_url + self.route}/orgs/{org_name}/actions/permissions",
                        f"{self.base_url + self.route}/orgs/{org_name}/actions/permissions/repositories",
                        f"{self.base_url + self.route}/orgs/{org_name}/actions/permissions/selected-actions",
                        f"{self.base_url + self.route}/orgs/{org_name}/actions/permissions/workflow"
                    ]
                    
                    for endpoint in settings_endpoints:
                        try:
                            settings_response = self.session.get(endpoint, headers=headers)
                            if settings_response.status_code == 200:
                                settings_data = settings_response.json()
                                # Look for any configuration that might contain sensitive data
                                if isinstance(settings_data, dict):
                                    for key, value in settings_data.items():
                                        if key in ['allowed_actions', 'selected_actions_url', 'enabled_repositories', 'default_workflow_permissions']:
                                            variables.append({
                                                'name': f'org_actions_{key}',
                                                'type': 'organization_config',
                                                'value': str(value),
                                                'created_at': '',
                                                'updated_at': '',
                                                'visibility': 'organization'
                                            })
                        except:
                            continue
                    
        except requests.RequestException as e:
            if self.is_fine_grained and not getattr(self, 'json_mode', False):
                print(f"        ⚠️  Fine-grained PAT may not have required permissions for {org_name}")
            pass  # Organization might not be accessible or variables not available
        
        return variables

    def generate_json_output(self, org_name: Optional[str] = None, include_variables: bool = False) -> Dict:
        """Generate a simplified JSON output for use in other scripts."""
        output = {
            "token_valid": False,
            "user_info": {},
            "organizations": [],
            "scopes": [],
            "rate_limit": {},
            "repositories": {
                "total": 0,
                "private": [],
                "public": []
            },
            "summary": {
                "total_repos": 0,
                "private_count": 0,
                "public_count": 0,
                "owners": [],
                "organizations_count": 0
            }
        }
        
        # Check token validity
        if not self.check_token_validity():
            return output
        
        output["token_valid"] = True
        
        # Get user info
        user_info = self.get_user_info()
        if user_info:
            output["user_info"] = {
                "login": user_info.get("login"),
                "name": user_info.get("name"),
                "type": user_info.get("type"),
                "id": user_info.get("id"),
                "email": user_info.get("email"),
                "company": user_info.get("company"),
                "location": user_info.get("location"),
                "public_repos": user_info.get("public_repos", 0),
                "private_repos": user_info.get("total_private_repos", 0),
                "followers": user_info.get("followers", 0),
                "following": user_info.get("following", 0)
            }
        
        # Get organizations
        organizations = self.get_user_organizations(suppress_warnings=True)
        output["organizations"] = [
            {
                "login": org["login"],
                "name": org["name"],
                "description": org["description"],
                "role": org["role"],
                "public_repos": org["public_repos"],
                "private_repos": org["private_repos"],
                "url": org["url"]
            }
            for org in organizations
        ]
        
        # Get scopes
        output["scopes"] = self.get_token_scopes()
        
        # Get rate limit
        rate_limit = self.get_rate_limit_info()
        if rate_limit and 'rate' in rate_limit:
            core_rate = rate_limit['rate']
            output["rate_limit"] = {
                "limit": core_rate.get("limit"),
                "remaining": core_rate.get("remaining"),
                "reset": core_rate.get("reset")
            }
        
        # Get repositories
        repositories = self.get_accessible_repositories()
        if org_name:
            org_repos = self.get_organization_repositories(org_name)
            repositories.extend(org_repos)
        
        # Process repositories
        private_repos = []
        public_repos = []
        owners = set()
        
        for repo in repositories:
            owners.add(repo['owner'])
            
            repo_data = {
                "name": repo['name'],
                "owner": repo['owner'],
                "permissions": {
                    "admin": repo.get('permissions', {}).get('admin', False),
                    "push": repo.get('permissions', {}).get('push', False),
                    "pull": repo.get('permissions', {}).get('pull', False)
                },
                "url": repo['url']
            }
            
            if repo['private']:
                private_repos.append(repo_data)
            else:
                public_repos.append(repo_data)
        
        output["repositories"]["private"] = private_repos
        output["repositories"]["public"] = public_repos
        output["repositories"]["total"] = len(repositories)
        
        # Summary
        output["summary"] = {
            "total_repos": len(repositories),
            "private_count": len(private_repos),
            "public_count": len(public_repos),
            "owners": sorted(list(owners)),
            "organizations_count": len(organizations)
        }
        
        # Include variables if requested
        if include_variables:
            variables_info = self.enumerate_variables_silent("all")
            output["variables"] = variables_info
        
        return output

    def enumerate_variables_silent(self, target_type: str = "all", target_name: Optional[str] = None) -> Dict:
        """Enumerate GitHub variables at different scopes without printing output"""
        variables_info = {
            "user_variables": [],
            "repository_variables": {},
            "organization_variables": {},
            "summary": {
                "total_user_variables": 0,
                "total_repo_variables": 0,
                "total_org_variables": 0,
                "accessible_repos": 0,
                "accessible_orgs": 0
            }
        }
        
        # Get user variables if requested
        if target_type in ["all", "user"]:
            user_vars = self.get_user_variables()
            variables_info["user_variables"] = user_vars
            variables_info["summary"]["total_user_variables"] = len(user_vars)
        
        # Get repository variables if requested
        if target_type in ["all", "repo", "repository"]:
            # If specific repository is requested
            if target_name and target_type in ["repo", "repository"]:
                repo_vars = self.get_repository_variables(target_name)
                variables_info["repository_variables"][target_name] = repo_vars
                variables_info["summary"]["total_repo_variables"] += len(repo_vars)
                variables_info["summary"]["accessible_repos"] = 1
            else:
                # Get all accessible repositories
                repositories = self.get_accessible_repositories()
                variables_info["summary"]["accessible_repos"] = len(repositories)
                
                for repo in repositories:
                    repo_name = repo['name']
                    repo_vars = self.get_repository_variables(repo_name)
                    
                    if repo_vars:
                        variables_info["repository_variables"][repo_name] = repo_vars
                        variables_info["summary"]["total_repo_variables"] += len(repo_vars)
        
        # Get organization variables if requested
        if target_type in ["all", "org", "organization"]:
            # If specific organization is requested
            if target_name and target_type in ["org", "organization"]:
                org_vars = self.get_organization_variables(target_name)
                variables_info["organization_variables"][target_name] = org_vars
                variables_info["summary"]["total_org_variables"] += len(org_vars)
                variables_info["summary"]["accessible_orgs"] = 1
            else:
                # Get all accessible organizations
                organizations = self.get_user_organizations(suppress_warnings=True)
                variables_info["summary"]["accessible_orgs"] = len(organizations)
                
                if organizations:
                    for org in organizations:
                        org_name = org['login']
                        org_vars = self.get_organization_variables(org_name)
                        
                        if org_vars:
                            variables_info["organization_variables"][org_name] = org_vars
                            variables_info["summary"]["total_org_variables"] += len(org_vars)
        
        return variables_info


class EnhancedTokenEnumerator:
    """Enhanced multi-platform token enumerator with full GitHub functionality and enhanced NPM access detection"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.detector = TokenDetector()
        self.npm_checker = NPMTokenChecker(debug)
        
        # File extensions to scan for tokens
        self.file_extensions = [
            '.js', '.json', '.yml', '.yaml', '.env', '.npmrc', '.gitignore',
            '.dockerfile', '.docker', '.sh', '.bat', '.ps1', '.py', '.rb',
            '.php', '.go', '.rs', '.java', '.cs', '.cpp', '.c', '.h',
            '.md', '.txt', '.conf', '.config', '.ini', '.properties', '.toml'
        ]

    def run_github_analysis(self, token: str, ghe: str = None,
                           org_name: Optional[str] = None,
                           json_output: bool = False, download: bool = False, 
                           download_path: str = "repos", download_type: str = "all",
                           enumerate_vars: bool = False, var_target: str = "all",
                           var_name: Optional[str] = None):
        """Run comprehensive GitHub PAT analysis with all original features"""
        checker = GitHubPATChecker(token, ghe)
        
        # Set JSON mode flag for the checker to suppress warnings
        checker.json_mode = json_output
        
        if json_output:
            output = checker.generate_json_output(org_name, enumerate_vars)
            print(json.dumps(output, indent=2))
            return
        
        # Check if token is valid
        if not checker.check_token_validity():
            print("❌ Invalid GitHub token or network error")
            return
        
        print("✅ GitHub token is valid")
        
        # Show token type information
        if checker.is_fine_grained:
            print("🔍 Token Type: Fine-grained Personal Access Token")
            print("   ⚠️  Fine-grained PATs have more restricted permissions")
            print("   ⚠️  Variable access depends on specific repository permissions granted")
        else:
            print("🔍 Token Type: Classic Personal Access Token")
        
        # Get user info
        user_info = checker.get_user_info()
        if user_info:
            print(f"\n👤 Authenticated as: {user_info.get('login', 'Unknown')}")
            print(f"   Name: {user_info.get('name', 'Not set')}")
            print(f"   Account type: {user_info.get('type', 'Unknown')}")
            if user_info.get('email'):
                print(f"   Email: {user_info.get('email')}")
            if user_info.get('company'):
                print(f"   Company: {user_info.get('company')}")
            if user_info.get('location'):
                print(f"   Location: {user_info.get('location')}")
            print(f"   Public repos: {user_info.get('public_repos', 0)}")
            print(f"   Private repos: {user_info.get('total_private_repos', 0)}")
            print(f"   Followers: {user_info.get('followers', 0)}")
            print(f"   Following: {user_info.get('following', 0)}")
        
        # Get organizations
        organizations = checker.get_user_organizations()
        if organizations:
            print(f"\n🏢 Organization Memberships ({len(organizations)} total):")
            for org in organizations:
                role_emoji = "👑" if org['role'] == 'admin' else "👤"
                print(f"   {role_emoji} {org['login']} ({org['role']})")
                if org['name']:
                    print(f"      Name: {org['name']}")
                if org['description']:
                    print(f"      Description: {org['description']}")
                print(f"      Public repos: {org['public_repos']}")
                print(f"      Private repos: {org['private_repos']}")
                print(f"      URL: {org['url']}")
                print()
        else:
            print(f"\n🏢 Organization Memberships: None found")
        
        # Get token scopes
        scopes = checker.get_token_scopes()
        print(f"\n🔑 Token Scopes ({len(scopes)} total):")
        if scopes:
            for scope in scopes:
                print(f"   • {scope}")
            checker.print_scope_descriptions(scopes)
        else:
            print("   No scopes found (this might indicate a classic token with no explicit scopes)")
        
        # Get rate limit info
        rate_limit = checker.get_rate_limit_info()
        if rate_limit and 'rate' in rate_limit:
            core_rate = rate_limit['rate']
            print(f"\n📊 Rate Limit Status:")
            print(f"   Limit: {core_rate.get('limit', 'Unknown')}")
            print(f"   Remaining: {core_rate.get('remaining', 'Unknown')}")
            print(f"   Reset time: {core_rate.get('reset', 'Unknown')}")
        
        # Get accessible repositories
        print(f"\n📁 Accessible Repositories:")
        repositories = checker.get_accessible_repositories()
        
        if org_name:
            org_repos = checker.get_organization_repositories(org_name)
            repositories.extend(org_repos)
        
        if repositories:
            # Separate private and public repositories
            private_repos = [repo for repo in repositories if repo['private']]
            public_repos = [repo for repo in repositories if not repo['private']]
            
            print(f"   Found {len(repositories)} accessible repositories:")
            print(f"   • {len(private_repos)} private repositories")
            print(f"   • {len(public_repos)} public repositories")
            
            # Display private repositories
            if private_repos:
                print(f"\n🔒 Private Repositories ({len(private_repos)}):")
                
                # Group private repos by owner
                private_by_owner = {}
                for repo in private_repos:
                    owner = repo['owner']
                    if owner not in private_by_owner:
                        private_by_owner[owner] = []
                    private_by_owner[owner].append(repo)
                
                for owner, repos in private_by_owner.items():
                    print(f"\n   📂 {owner} ({len(repos)} private repos):")
                    for repo in repos:
                        permissions = repo.get('permissions', {})
                        perm_str = []
                        if permissions.get('admin'):
                            perm_str.append("admin")
                        elif permissions.get('push'):
                            perm_str.append("write")
                        elif permissions.get('pull'):
                            perm_str.append("read")
                        
                        perm_display = f"({', '.join(perm_str)})" if perm_str else ""
                        print(f"      • {repo['name']} {perm_display}")
            
            # Display public repositories
            if public_repos:
                print(f"\n🔓 Public Repositories ({len(public_repos)}):")
                
                # Group public repos by owner
                public_by_owner = {}
                for repo in public_repos:
                    owner = repo['owner']
                    if owner not in public_by_owner:
                        public_by_owner[owner] = []
                    public_by_owner[owner].append(repo)
                
                for owner, repos in public_by_owner.items():
                    print(f"\n   📂 {owner} ({len(repos)} public repos):")
                    for repo in repos:
                        permissions = repo.get('permissions', {})
                        perm_str = []
                        if permissions.get('admin'):
                            perm_str.append("admin")
                        elif permissions.get('push'):
                            perm_str.append("write")
                        elif permissions.get('pull'):
                            perm_str.append("read")
                        
                        perm_display = f"({', '.join(perm_str)})" if perm_str else ""
                        print(f"      • {repo['name']} {perm_display}")
        else:
            print("   No repositories found or accessible")
        
        # Enumerate variables if requested
        if enumerate_vars:
            if checker.is_fine_grained:
                print(f"\n⚠️  Fine-grained PAT Variable Access:")
                print("   • Fine-grained PATs only have access to specifically granted repositories")
                print("   • User-level variables are typically not accessible")
                print("   • Organization access depends on granted permissions")
                print("   • Repository access is limited to permitted repositories only")
                print("")
            checker.enumerate_variables(var_target, var_name)
        
        # Download repositories if requested
        if download:
            download_stats = checker.download_all_repositories(org_name, download_path, download_type)
            if download_stats["total"] > 0:
                print(f"\n🎉 Download session complete!")
                print(f"   Check your files in: {os.path.abspath(download_path)}")

    def run_npm_analysis(self, token: str, json_output: bool = False):
        """Run NPM token analysis with enhanced access detection"""
        
        # If JSON output is requested, generate and print JSON
        if json_output:
            output = self.npm_checker.generate_npm_json_output(token)
            print(json.dumps(output, indent=2))
            return
        
        if self.debug:
            print(f"🔍 Analyzing NPM token: {token[:8]}...{token[-4:]}")
            print(f"   Token length: {len(token)}")
            print(f"   Token starts with: {token[:8]}")
        
        # Check if token is valid
        is_valid, validation_info = self.npm_checker.validate_npm_token(token)
        if not is_valid:
            print("❌ Invalid NPM token or network error")
            if 'error' in validation_info:
                print(f"   Error: {validation_info['error']}")
            if self.debug:
                print(f"   Validation info: {validation_info}")
            return
        
        print("✅ NPM token is valid")
        
        # Get comprehensive user info
        user_info = self.npm_checker.get_comprehensive_npm_user_info(token)
        if user_info:
            print(f"\n👤 User Profile:")
            print(f"   Username: {user_info.get('username', 'Unknown')}")
            print(f"   Name: {user_info.get('name', 'Not set')}")
            print(f"   Email: {user_info.get('email', 'Not set')}")
            print(f"   Type: {user_info.get('type', 'user')}")
            
            if user_info.get('created'):
                print(f"   Account created: {user_info.get('created')[:10]}")
            
            # Additional profile information
            if user_info.get('homepage'):
                print(f"   Homepage: {user_info.get('homepage')}")
            if user_info.get('github'):
                print(f"   GitHub: {user_info.get('github')}")
            if user_info.get('twitter'):
                print(f"   Twitter: {user_info.get('twitter')}")
            
            # Security information
            print(f"\n🔒 Security Status:")
            print(f"   • Two-Factor Auth: {'✅ Enabled' if user_info.get('tfa_enabled') else '❌ Disabled'}")
            if user_info.get('tfa_mode'):
                print(f"   • 2FA Mode: {user_info.get('tfa_mode')}")
            print(f"   • Email Verified: {'✅' if user_info.get('email_verified') else '❌'}")
            
            # Package statistics
            if user_info.get('package_statistics'):
                stats = user_info['package_statistics']
                print(f"\n📊 Package Statistics:")
                print(f"   • Total packages: {stats.get('total_packages', 0)}")
                print(f"   • Monthly downloads: {stats.get('total_monthly_downloads', 0):,}")
                
                breakdown = stats.get('package_breakdown', {})
                print(f"   • Scoped packages: {breakdown.get('scoped', 0)}")
                print(f"   • Unscoped packages: {breakdown.get('unscoped', 0)}")
                print(f"   • Private packages: {breakdown.get('private', 0)}")
                print(f"   • Public packages: {breakdown.get('public', 0)}")
            
            # Starred packages
            if user_info.get('starred_packages'):
                starred = user_info['starred_packages']
                if isinstance(starred, list) and len(starred) > 0:
                    print(f"\n⭐ Starred Packages ({len(starred)} total):")
                    for star in starred[:5]:  # Show first 5
                        print(f"   • {star}")
                    if len(starred) > 5:
                        print(f"   ... and {len(starred) - 5} more")
            
            # Followers/Following
            if user_info.get('followers'):
                followers = user_info['followers']
                if isinstance(followers, list):
                    print(f"\n👥 Social:")
                    print(f"   • Followers: {len(followers)}")
                    
        elif self.debug:
            print("⚠️  Could not retrieve user info")
        
        # Get detailed token information
        token_details = self.npm_checker.get_npm_token_details(token)
        
        # Show token information
        token_info = token_details.get('token_info', {})
        if token_info:
            print(f"\n🔑 Token Details:")
            print(f"   • Type: {'Read-only' if token_info.get('readonly') else 'Read/Write'}")
            print(f"   • Automation: {'Yes' if token_info.get('automation') else 'No'}")
            if token_info.get('cidr_whitelist'):
                print(f"   • CIDR Restrictions: {', '.join(token_info.get('cidr_whitelist', []))}")
            if token_info.get('created'):
                print(f"   • Created: {token_info.get('created')[:10]}")
        
        # Get token permissions
        if is_valid:
            permissions = validation_info.get('permissions', {})
            print(f"\n🔑 Token Permissions:")
            print(f"   • Read: {'✅' if permissions.get('read') else '❌'}")
            print(f"   • Publish: {'✅' if permissions.get('publish') else '❌'}")
            print(f"   • Admin: {'✅' if permissions.get('admin') else '❌'}")
            
            # Show additional permission details
            if permissions.get('details'):
                details = permissions['details']
                if details.get('readonly') is not None:
                    print(f"   • Read-only mode: {'Yes' if details.get('readonly') else 'No'}")
        
        # Show accessible scopes
        scopes = token_details.get('scopes', [])
        if scopes:
            print(f"\n🏢 Accessible Scopes ({len(scopes)} total):")
            for scope in scopes:
                print(f"   • {scope}")
        
        # Show organizations
        organizations = token_details.get('organizations', [])
        if organizations:
            print(f"\n🏢 Organization Memberships ({len(organizations)} total):")
            for org in organizations:
                print(f"   • {org['name']} ({org.get('role', 'unknown')} role)")
                print(f"     Scope: {org.get('scope', 'unknown')}")
        
        # Get accessible packages with enhanced access detection
        packages = token_details.get('packages', [])
        print(f"\n📦 Accessible Packages ({len(packages)} total):")
        if packages:
            # Group packages by scope/organization
            scoped_packages = {}
            unscoped_packages = []
            
            for package in packages:
                if package.get('scope'):
                    scope = package['scope']
                    if scope not in scoped_packages:
                        scoped_packages[scope] = []
                    scoped_packages[scope].append(package)
                elif '/' in package['name']:
                    scope = package['name'].split('/')[0]
                    if scope not in scoped_packages:
                        scoped_packages[scope] = []
                    scoped_packages[scope].append(package)
                else:
                    unscoped_packages.append(package)
            
            # Show scoped packages with enhanced access display
            for scope, scope_packages in scoped_packages.items():
                print(f"\n   📂 {scope} scope ({len(scope_packages)} packages):")
                for package in scope_packages[:10]:  # Show first 10 per scope
                    role = package.get('role', 'unknown')
                    access = package.get('access', 'unknown')
                    version = package.get('version', '')
                    version_str = f" v{version}" if version and version != 'unknown' else ""
                    
                    # Use enhanced access display
                    access_display = self.npm_checker.format_access_display(access, role)
                    print(f"      • {package['name']}{version_str} - {access_display}")
                    
                    if package.get('description'):
                        print(f"        {package['description'][:60]}...")
                
                if len(scope_packages) > 10:
                    print(f"      ... and {len(scope_packages) - 10} more packages")
            
            # Show unscoped packages with enhanced access display
            if unscoped_packages:
                print(f"\n   📦 Unscoped packages ({len(unscoped_packages)}):")
                for package in unscoped_packages[:10]:  # Show first 10
                    role = package.get('role', 'unknown')
                    access = package.get('access', 'unknown')
                    version = package.get('version', '')
                    version_str = f" v{version}" if version and version != 'unknown' else ""
                    
                    # Use enhanced access display
                    access_display = self.npm_checker.format_access_display(access, role)
                    print(f"      • {package['name']}{version_str} - {access_display}")
                    
                    if package.get('description'):
                        print(f"        {package['description'][:60]}...")
                
                if len(unscoped_packages) > 10:
                    print(f"      ... and {len(unscoped_packages) - 10} more packages")
        
        if not packages:
            print("   No packages found or accessible")
            if self.debug:
                print("   This could mean:")
                print("   • Token has no package access")
                print("   • User has no published packages")
                print("   • Token permissions are read-only")

    def scan_for_tokens(self, target_path: str) -> Dict:
        """Scan for all types of tokens in files"""
        results = {
            'tokens': [],
            'files_scanned': 0,
            'scan_path': target_path
        }
        
        target = Path(target_path)
        
        if target.is_file():
            files_to_scan = [target]
        elif target.is_dir():
            files_to_scan = []
            for ext in self.file_extensions:
                files_to_scan.extend(target.rglob(f'*{ext}'))
            # Also scan common config files without extensions
            for config_file in ['.npmrc', '.env', '.gitconfig', '.netrc']:
                files_to_scan.extend(target.rglob(config_file))
        else:
            print(f"❌ Target path {target_path} does not exist")
            return results
        
        print(f"🔍 Scanning {len(files_to_scan)} files for tokens...")
        
        for file_path in files_to_scan:
            try:
                if file_path.is_file():
                    results['files_scanned'] += 1
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Extract tokens using the detector
                    found_tokens = self.detector.extract_tokens_from_text(content, str(file_path))
                    
                    # Add file and line information
                    for token_info in found_tokens:
                        token_info['file'] = str(file_path)
                        token_info['line'] = content[:content.find(token_info['token'])].count('\n') + 1
                        results['tokens'].append(token_info)
                    
            except Exception as e:
                if self.debug:
                    print(f"Error scanning {file_path}: {str(e)}")
        
        return results

    def run_token_scan(self, scan_path: str, ghe: str):
        """Run comprehensive token scanning"""
        print(f"\n🔍 Multi-Platform Token Discovery")
        print("=" * 50)
        print(f"Scanning path: {scan_path}")
        
        # Scan for tokens
        scan_results = self.scan_for_tokens(scan_path)
        
        # Group by type for summary
        by_type = {}
        for token_info in scan_results['tokens']:
            token_type = token_info['type']
            if token_type not in by_type:
                by_type[token_type] = 0
            by_type[token_type] += 1
        
        print(f"\n📊 Scan Results:")
        print(f"   Files scanned: {scan_results['files_scanned']}")
        print(f"   Total tokens found: {len(scan_results['tokens'])}")
        
        for token_type, count in by_type.items():
            print(f"   • {token_type.upper()} tokens: {count}")
        
        if scan_results['tokens']:
            print(f"\n🔍 Validating found tokens...")
            
            # Validate each token
            for token_info in scan_results['tokens']:
                token = token_info['token']
                token_type = token_info['type']
                
                print(f"\n🔑 {token_type.upper()} Token: {token[:8]}...{token[-4:]}")
                print(f"   File: {token_info['file']}:{token_info['line']}")
                
                if token_type == 'github':
                    checker = GitHubPATChecker(token, ghe)
                    if checker.check_token_validity():
                        print("   ✅ VALID TOKEN")
                        user_info = checker.get_user_info()
                        print(f"   👤 User: {user_info.get('login', 'Unknown')}")
                        repos = checker.get_accessible_repositories()
                        orgs = checker.get_user_organizations(suppress_warnings=True)
                        print(f"   📁 Repositories: {len(repos)}")
                        print(f"   🏢 Organizations: {len(orgs)}")
                        print("   ⚠️  SECURITY RISK: This token should be revoked immediately!")
                    else:
                        print("   ❌ Invalid or expired token")
                
                elif token_type == 'npm':
                    is_valid, validation_info = self.npm_checker.validate_npm_token(token)
                    if is_valid:
                        print("   ✅ VALID TOKEN")
                        user_info = self.npm_checker.get_npm_user_info(token)
                        packages = self.npm_checker.get_npm_packages(token)
                        print(f"   👤 User: {user_info.get('username', 'Unknown')}")
                        print(f"   📦 Packages: {len(packages)}")
                        permissions = validation_info.get('permissions', {})
                        print(f"   🔑 Permissions: R={permissions.get('read', False)}, W={permissions.get('publish', False)}")
                        
                        # Show package access breakdown
                        if packages:
                            access_breakdown = {}
                            for package in packages:
                                access = package.get('access', 'unknown')
                                access_breakdown[access] = access_breakdown.get(access, 0) + 1
                            
                            access_summary = ", ".join([f"{access}={count}" for access, count in access_breakdown.items()])
                            print(f"   📊 Package Access: {access_summary}")
                        
                        print("   ⚠️  SECURITY RISK: This token should be revoked immediately!")
                    else:
                        print("   ❌ Invalid or expired token")
                        print(f"   Error: {validation_info.get('error', 'Unknown')}")
                
                else:
                    print("   ❓ Token type not fully supported for validation")
        
        else:
            print("\n✅ No tokens found in scanned files")


def show_version():
    """Display version information"""
    print(f"""
gimmePATz v{__version__} - Author: {__author__}
GitHub: https://github.com/6mile/gimmepatz
    """)

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced multi-platform token enumeration and analysis tool with advanced NPM access detection"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information and exit"
    )
    parser.add_argument(
        "token",
        nargs="?",
        help="Token to analyze (automatically detects type)"
    )
    parser.add_argument(
        "--ghe",
        help="Use a GitHub Enterprise URL"
    )
    parser.add_argument(
        "--scan",
        help="Path to scan for tokens (file or directory)"
    )
    parser.add_argument(
        "--org",
        help="Also check repositories in a specific GitHub organization"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format (GitHub only)"
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download all accessible repositories using git clone (GitHub only)"
    )
    parser.add_argument(
        "--download-path",
        default="repos",
        help="Base path for downloaded repositories (default: repos)"
    )
    parser.add_argument(
        "--download-type",
        choices=["all", "private", "public"],
        default="all",
        help="Type of repositories to download (default: all)"
    )
    parser.add_argument(
        "--variables", "--var",
        action="store_true",
        help="Enumerate GitHub variables and secrets (GitHub only)"
    )
    parser.add_argument(
        "--var-target",
        choices=["all", "user", "repo", "repository", "org", "organization"],
        default="all",
        help="Target scope for variable enumeration (default: all)"
    )
    parser.add_argument(
        "--var-name",
        help="Specific repository or organization name for targeted variable enumeration"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    
    args = parser.parse_args()
    
    # Handle version flag
    if args.version:
        show_version()
        sys.exit(0)
    
    # Show Title/banner only if not JSON output
    if not args.json:
        print(f"""
       _                         ______  ___ _____
      (_)                        | ___ \/ _ \_   _|
  __ _ _ _ __ ___  _ __ ___   ___| |_/ / /_\ \| |____
 / _` | | '_ ` _ \| '_ ` _ \ / _ \  __/|  _  || |_  /
| (_| | | | | | | | | | | | |  __/ |   | | | || |/ /
 \__, |_|_| |_| |_|_| |_| |_|\___\_|   \_| |_/\_/___|
  __/ |
 |___/            "Personal Access Token recon tool"
 ----------------------------------------------------
                                          by @6mile
        """)
    
    # Initialize the enhanced enumerator
    enumerator = EnhancedTokenEnumerator(debug=args.debug)
    detector = TokenDetector()
    
    # Run appropriate analysis
    if args.scan:
        enumerator.run_token_scan(args.scan, args.ghe)
    elif args.token:
        # Detect token type and run appropriate analysis
        token_type = detector.detect_token_type(args.token)
        
        if token_type == 'github':
            enumerator.run_github_analysis(
                args.token,
                args.ghe,
                args.org, 
                args.json, 
                args.download, 
                args.download_path, 
                args.download_type,
                args.variables,
                args.var_target,
                args.var_name
            )
        elif token_type == 'npm':
            enumerator.run_npm_analysis(args.token, args.json)
        else:
            print(f"❌ Unsupported or unrecognized token type: {token_type}")
            print("   Supported types: GitHub (ghp_*), NPM (npm_*)")
    else:
        print("❌ Please provide a token to analyze or path to scan")
        print("   Examples:")
        print("     ./gimmepatz.py ghp_1234567890abcdef")
        print("     ./gimmepatz.py npm_1234567890abcdef")
        print("     ./gimmepatz.py --ghe https://your.enterprise.tld")
        print("     ./gimmepatz.py --scan /path/to/project")
        print("     ./gimmepatz.py ghp_token --org myorg --download")
        print("     ./gimmepatz.py ghp_token --variables")
        print("     ./gimmepatz.py ghp_token --var --var-target repo --var-name owner/repo")
        print("     ./gimmepatz.py --version")
        print("   Use --help for more information")


if __name__ == "__main__":
    main()
