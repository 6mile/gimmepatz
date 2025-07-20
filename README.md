![gimmePATz](images/gimmepatz-github-banner.png)

## :smirk_cat: gimmePATz :smirk_cat: - Personal Access Token (PAT) recon tool

Have you ever found a GitHub or a NPM personal access token (PAT) and wondered "Is this valid?" or "I wonder what a bad guy could do with this?" Well, if so, I've got the tool for you! 

Introducing gimmePatz, a comprehensive reconnaissance tool for PATs. gimmePATz will tell you if a PAT is valid, and what kind of PAT it is.  It provides information about the user account that created the PAT, including what organizations that user is part of and how many followers they have.  gimmePATz will show you what scopes a PAT has and what variables or secrets the PAT has access to.  gimmePATz will list what repositories, NPM packages or GitHub Organisations the PAT is attached to as well, and tell you exactly what permissions the PAT has to each resource.  This tool is designed for offensive security practitioners, like bug bounty hunters, pentesters and red teams.  By using this tool, you agree to use it in a legal context.

You can point gimmePATz at a file and it will find all the PATs in that file and let you know if they are valid.  gimmepatz supports JSON output as well, so you can save the output in JSON, and/or pipe the output of gimmePATz into other tools like jq.  You can see some examples of the different ways to use gimmePATz in the "Advanced Usage" section below.

### Features

- 🔍 **Token Validation** - Verify if the GitHub or NPM PAT you found is valid and what does it have access to?
- 🔑 **Permission Analysis** - Detailed breakdown of token scopes with descriptions
- 👤 **User Information** - Details about the user that created the PAT
- 📁 **Repository Discovery** - Find all repositories attached to this PAT
- ☢️  **Enumerate Variables & Secrets** - Identify any GitHub Variables or Secrets the PAT has access to
- 📋 **JSON Output** - Machine-readable format for automation
- 🔒 **Privacy Separation** - Clearly distinguish between private and public repos
- 🏢 **Organization Support** - Tells you what organizations are attached to this PAT
- ⬇️  **Download Repos/Packages** - Download files and repos that are found


### Basic Usage

```bash
gimmepatz.py TOKEN
```
### Prerequisites
- Python 3.6+
- `requests` library # ```pip install requests```
- `git` (for repository downloading)

### Advanced Usage

```bash
# Discover secrets and variables
gimmepatz.py TOKEN --variables

# Include organization repositories
gimmepatz.py TOKEN --org GITHUB_ORGANIZATION

# JSON output for scripting
gimmepatz.py TOKEN --json

# Combined: organization repos + JSON output
gimmepatz.py TOKEN --org GITHUB_ORGANIZATION --json

# Save the output of gimmePATz in JSON output to a file
gimmepatz.py TOKEN --variables --org target-org --json > assessment.json

# Download all accessible repositories
gimmepatz.py TOKEN --download

# Download only private repositories
gimmepatz.py TOKEN --download --download-type private

# Custom download location
gimmepatz.py TOKEN --download --download-path ./target-repos

# Scan a file to see if it has any PATs in it
gimmepatz.py --scan ./example-file.json
```

### Installation

**Clone or download the script**
```bash
git clone https://github.com/6mile/gimmepatz.git
cd ./gimmepatz/ && chmod u+x ./gimmepatz.py
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--json` | Output results in JSON format |
| `--variables`, `--var` | Enumerate GitHub variables and secrets |
| `--var-target` | Target scope: `all`, `user`, `repo`, `org` |
| `--var-name` | Specific repository or organization name |
| `--download` | Download all accessible repositories |
| `--download-path` | Custom download directory (default: `repos`) |
| `--download-type` | Filter: `all`, `private`, `public` |
| `--org` | Include specific GitHub organization analysis |
| `--debug` | Enable verbose debug output |
| `--scan` | Scan local files for PATs |

### Output Examples

```
       _                         ______  ___ _____
      (_)                        | ___ \/ _ \_   _|
  __ _ _ _ __ ___  _ __ ___   ___| |_/ / /_\ \| |____
 / _` | | '_ ` _ \| '_ ` _ \ / _ \  __/|  _  || |_  /
| (_| | | | | | | | | | | | |  __/ |   | | | || |/ /
 \__, |_|_| |_| |_|_| |_| |_|\___\_|   \_| |_/\_/___|
  __/ |
 |___/             "Personal Access Token recon tool"
 ----------------------------------------------------
                                           by @6mile

✅ Token is valid

👤 Authenticated as: octocat
   Name: Octocat Maclean
   Account type: User
   Public repos: 4
   Private repos: 3
   Followers: 9714
   Following: 731

🏢 Organization Memberships (2 total):
   👤 Space-Force-Beta (member)
      Name: Space-Force-Beta
      Description: Building cool stuff for space
      Public repos: 2
      Private repos: 1
      URL: https://github.com/Space-Force-Beta

   👑 ThrifyBank (admin)
      Description: The thriftiest Neo Bank in Kansas!
      Public repos: 1
      Private repos: 5
      URL: https://github.com/thrifybank-kansas

🔑 Token Scopes (14 total):
   • codespace:secrets
   • notifications
   • read:audit_log
   • read:discussion
   • read:enterprise
   • read:org
   • read:packages
   • read:project
   • read:public_key
   • read:repo_hook
   • read:user
   • repo
   • user:email
   • workflow

Scope Descriptions:
--------------------------------------------------
  repo: Full access to repositories
  user: Access to user profile information
  notifications: Access to notifications

📊 Rate Limit Status:
   Limit: 5000
   Remaining: 4999
   Reset time: 1234567890

📁 Accessible Repositories:
   Found 25 accessible repositories:
   • 15 private repositories
   • 10 public repositories

🔒 Private Repositories (9):

   📂 octocat (3 private repos):
      • octocat/internal-api (admin)
      • octocat/database (admin)
      • octocat/external-api (admin)

   📂 Space-Force-Beta (1 private repos):
      • Space-Force-Beta/destrukto-beam (admin)

   📂 ThriftyBank (5 private repos):
      • thriftybank-kansas/web (admin)
      • thriftybank-kansas/docker (admin)
      • thriftybank-kansas/database-int (admin)
      • thriftybank-kansas/bank-vault (admin)
      • thriftybank-kansas/SAAS-PORTAL (admin)

🔓 Public Repositories (7):

   📂 octocat (4 public repos):
      • octocat/sdk (admin)
      • octocat/helpdesk-docs (admin)
      • octocat/aws-sdk-helpers (admin)
      • octocat/stinkyCaptain (admin)

   📂 Space-Force-Beta (1 public repos):
      • Space-Force-Beta/destrukto-beam (admin)

   📂 thrifybank-kansas (1 public repos):
      • thrifybank-kansas/node-restify (admin)
```

### JSON Output

```json
{
  "token_valid": true,
  "user_info": {
    "login": "octocat",
    "name": "The Octocat",
    "type": "User",
    "id": 1
  },
  "scopes": ["repo", "user", "notifications"],
  "rate_limit": {
    "limit": 5000,
    "remaining": 4999,
    "reset": 1234567890
  },
  "repositories": {
    "total": 25,
    "private": [
      {
        "name": "mycompany/internal-api",
        "owner": "mycompany",
        "permissions": {
          "admin": true,
          "push": true,
          "pull": true
        },
        "url": "https://github.com/mycompany/internal-api"
      }
    ],
    "public": [
      {
        "name": "octocat/awesome-project",
        "owner": "octocat",
        "permissions": {
          "admin": true,
          "push": true,
          "pull": true
        },
        "url": "https://github.com/octocat/awesome-project"
      }
    ]
  },
  "summary": {
    "total_repos": 25,
    "private_count": 15,
    "public_count": 10,
    "owners": ["mycompany", "octocat"]
  }
}
```

### Token Scopes Reference

| Scope | Description |
|-------|-------------|
| `repo` | Full access to repositories |
| `public_repo` | Access to public repositories only |
| `repo:status` | Access to commit status |
| `repo_deployment` | Access to deployment statuses |
| `user` | Access to user profile information |
| `user:email` | Access to user email addresses |
| `user:follow` | Access to follow/unfollow users |
| `admin:org` | Full access to organization, teams, and memberships |
| `write:org` | Write access to organization and teams |
| `read:org` | Read access to organization and teams |
| `gist` | Write access to gists |
| `notifications` | Access to notifications |
| `workflow` | Access to GitHub Actions workflows |
| `write:packages` | Write access to GitHub packages |
| `read:packages` | Read access to GitHub packages |
| `delete_repo` | Delete access to repositories |

### Security Best Practices

1. **Never commit tokens to version control**
2. **Use environment variables for tokens**
   ```bash
   export TOKEN="your_token_here"
   gimmepatz.py "$TOKEN"
   ```
3. **Regularly audit your tokens** using this tool
4. **Use minimal required scopes** for each token
5. **Set expiration dates** on your tokens when possible
6. **Rotate tokens regularly** as part of security hygiene

### Troubleshooting

### Common Issues

**"Invalid token or network error"**
- Verify your token is correct and active
- Check internet connectivity
- Ensure the token hasn't expired

**"No repositories found"**
- Token might have limited scopes
- User might not have access to any repositories
- Check if you need to include organization repositories with `--org`

**Rate limit exceeded**
- Wait for the rate limit to reset
- Use authenticated requests (this tool does automatically)
- Check rate limit status in the output

### Error Codes

- `200`: Success
- `401`: Bad credentials (invalid token)
- `403`: Rate limit exceeded or insufficient permissions
- `404`: Resource not found (user/organization doesn't exist)

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### License

This project is licensed under the MIT License - see the LICENSE file for details.

### Changelog

#### v0.1.0
- Initial release
- Token validation and scope analysis
- Repository discovery with privacy separation
- JSON output for automation
- Organization repository support
- ASCII art branding

#### v0.3.0
- Added NPM token validation
- Added GitHub Variables and Secrets detection
- Added ability to download repositories found via --download
---

**Made with ❤️  by @6mile for my offsec homies**
