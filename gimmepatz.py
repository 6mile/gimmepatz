#!/usr/bin/env python3
"""
GIMMEPATZ - GitHub Personal Access Token (PAT) Permission Checker

This script checks what permissions a GitHub PAT has and what repositories it can access.
"""

import argparse
import json
import os
import subprocess
import requests
import sys
from typing import Dict, List, Optional


class GitHubPATChecker:
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def check_token_validity(self) -> bool:
        """Check if the token is valid by making a simple API call."""
        try:
            response = self.session.get(f"{self.base_url}/user")
            return response.status_code == 200
        except requests.RequestException:
            return False

    def get_token_scopes(self) -> List[str]:
        """Get the scopes/permissions of the PAT."""
        try:
            response = self.session.get(f"{self.base_url}/user")
            if response.status_code == 200:
                # GitHub returns scopes in the X-OAuth-Scopes header
                scopes_header = response.headers.get('X-OAuth-Scopes', '')
                if scopes_header:
                    return [scope.strip() for scope in scopes_header.split(',')]
                else:
                    return []
            else:
                print(f"Error getting token scopes: {response.status_code}")
                return []
        except requests.RequestException as e:
            print(f"Error making request: {e}")
            return []

    def get_rate_limit_info(self) -> Dict:
        """Get rate limit information for the token."""
        try:
            response = self.session.get(f"{self.base_url}/rate_limit")
            if response.status_code == 200:
                return response.json()
            else:
                return {}
        except requests.RequestException:
            return {}

    def get_user_info(self) -> Dict:
        """Get information about the authenticated user."""
        try:
            response = self.session.get(f"{self.base_url}/user")
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
                # Get repositories for the authenticated user
                response = self.session.get(
                    f"{self.base_url}/user/repos",
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
                    print(f"Error getting repositories: {response.status_code}")
                    break
                    
            except requests.RequestException as e:
                print(f"Error making request: {e}")
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
                    f"{self.base_url}/user/orgs",
                    params={
                        "per_page": per_page,
                        "page": page
                    }
                )
                
                if response.status_code == 200:
                    orgs = response.json()
                    if not orgs:
                        break
                    
                    for org in orgs:
                        # Get user's login for role checking
                        user_login = self.get_user_info().get('login', '')
                        
                        organizations.append({
                            "login": org.get("login", ""),
                            "id": org.get("id", 0),
                            "name": org.get("name", ""),
                            "description": org.get("description", ""),
                            "public_repos": org.get("public_repos", 0),
                            "private_repos": org.get("total_private_repos", 0),
                            "url": org.get("html_url", f"https://github.com/{org.get('login', '')}"),
                            "role": self.get_user_role_in_org(org.get("login", ""), user_login)
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

    def get_user_role_in_org(self, org_login: str, user_login: str) -> str:
        """Get the user's role in a specific organization."""
        if not org_login or not user_login:
            return "unknown"
            
        try:
            # First try to get membership info
            response = self.session.get(f"{self.base_url}/orgs/{org_login}/memberships/{user_login}")
            
            if response.status_code == 200:
                membership = response.json()
                return membership.get("role", "member")
            elif response.status_code == 403:
                # Insufficient permissions to see detailed membership
                return "member"
            else:
                # Try alternative method - check if user can access org details
                org_response = self.session.get(f"{self.base_url}/orgs/{org_login}")
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
                    f"{self.base_url}/orgs/{org_name}/repos",
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

    def generate_json_output(self, org_name: Optional[str] = None) -> Dict:
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
        
        return output

    def run_analysis(self, org_name: Optional[str] = None, json_output: bool = False, 
                     download: bool = False, download_path: str = "repos", 
                     download_type: str = "all"):
        """Run the complete analysis of the PAT."""
        if json_output:
            output = self.generate_json_output(org_name)
            print(json.dumps(output, indent=2))
            return
        
        # ASCII Art Title
        print("""
       _                         ______  ___ _____
      (_)                        | ___ \/ _ \_   _|
  __ _ _ _ __ ___  _ __ ___   ___| |_/ / /_\ \| |____
 / _` | | '_ ` _ \| '_ ` _ \ / _ \  __/|  _  || |_  /
| (_| | | | | | | | | | | | |  __/ |   | | | || |/ /
 \__, |_|_| |_| |_|_| |_| |_|\___\_|   \_| |_/\_/___|
  __/ |
 |___/      "GitHub Personal Access Token recon tool"
 ----------------------------------------------------
                                           by @6mile
        """)

        # Check if token is valid
        if not self.check_token_validity():
            print("❌ Invalid token or network error")
            return
        
        print("✅ Token is valid")
        
        # Get user info
        user_info = self.get_user_info()
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
        organizations = self.get_user_organizations(suppress_warnings=False)
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
        scopes = self.get_token_scopes()
        print(f"\n🔑 Token Scopes ({len(scopes)} total):")
        if scopes:
            for scope in scopes:
                print(f"   • {scope}")
            self.print_scope_descriptions(scopes)
        else:
            print("   No scopes found (this might indicate a classic token with no explicit scopes)")
        
        # Get rate limit info
        rate_limit = self.get_rate_limit_info()
        if rate_limit and 'rate' in rate_limit:
            core_rate = rate_limit['rate']
            print(f"\n📊 Rate Limit Status:")
            print(f"   Limit: {core_rate.get('limit', 'Unknown')}")
            print(f"   Remaining: {core_rate.get('remaining', 'Unknown')}")
            print(f"   Reset time: {core_rate.get('reset', 'Unknown')}")
        
        # Get accessible repositories
        print(f"\n📁 Accessible Repositories:")
        repositories = self.get_accessible_repositories()
        
        if org_name:
            org_repos = self.get_organization_repositories(org_name)
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
        
        # Download repositories if requested
        if download:
            download_stats = self.download_all_repositories(org_name, download_path, download_type)
            if download_stats["total"] > 0:
                print(f"\n🎉 Download session complete!")
                print(f"   Check your files in: {os.path.abspath(download_path)}")


def main():
    parser = argparse.ArgumentParser(
        description="Check GitHub Personal Access Token permissions and accessible repositories"
    )
    parser.add_argument(
        "token",
        help="GitHub Personal Access Token"
    )
    parser.add_argument(
        "--org",
        help="Also check repositories in a specific organization"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format for use in other scripts"
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download all accessible repositories using git clone"
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
    
    args = parser.parse_args()
    
    checker = GitHubPATChecker(args.token)
    checker.run_analysis(args.org, args.json, args.download, args.download_path, args.download_type)


if __name__ == "__main__":
    main()
