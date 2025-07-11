![gimmePATz](gimmepatz-github-banner.png)

**gimmePATz - GitHub Personal Access Token Analysis & Repository Discovery Tool**

Have you ever found a GitHub PAT (personal access token) and wondered if it was valid or not?  If so, this tool is for you!  This tool should be useful for pentesters, bug bounty peeps and red team ninjas.  gimmepatz will tell you what scopes a PAT has, and it will tell you what repositories or GitHub Organizations the PAT is attached too as well.

gimmepatz supports JSON output as well, so you can run it inline with other offensive security tools and filter using jq.  You can see some of my examples below.

## Features

- 🔍 **Token Validation** - Verify if your PAT is valid and active
- 🔑 **Permission Analysis** - Detailed breakdown of token scopes with descriptions
- 📊 **Rate Limit Monitoring** - Current API usage and limits
- 👤 **User Information** - Details about the authenticated user
- 📁 **Repository Discovery** - Find all accessible repositories
- 🔒 **Privacy Separation** - Clearly distinguish between private and public repos
- 🏢 **Organization Support** - Include specific organization repositories
- 📋 **JSON Output** - Machine-readable format for automation
- 🎨 **Clean Interface** - User-friendly output with emojis and formatting

## Installation

### Prerequisites

- Python 3.6 or higher
- `requests` library

### Setup

1. **Clone or download the script**
   ```bash
   git clone https://github.com/6mile/gimmepatz.git
   ```

2. **Install dependencies**
   ```bash
   pip install requests
   ```

## Usage

### Basic Usage

```bash
python gimmepatz.py YOUR_GITHUB_TOKEN
```

### Advanced Usage

```bash
# Include organization repositories
python gimmepatz.py YOUR_GITHUB_TOKEN --org your-org-name

# JSON output for scripting
python gimmepatz.py YOUR_GITHUB_TOKEN --json

# Combined: organization repos + JSON output
python gimmepatz.py YOUR_GITHUB_TOKEN --org your-org-name --json
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `token` | GitHub Personal Access Token (required) |
| `--org ORG_NAME` | Include repositories from a specific organization |
| `--json` | Output results in JSON format for scripting |
| `--help` | Show help message and exit |

## Output Examples

### Human-Readable Output

```
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

✅ Token is valid

👤 Authenticated as: octocat
   Name: The Octocat
   Account type: User

🔑 Token Scopes (3 total):
   • repo
   • user
   • notifications

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

🔒 Private Repositories (15):

   📂 mycompany (8 private repos):
      • mycompany/internal-api (admin)
      • mycompany/secret-project (write)
      • mycompany/config-files (read)

🔓 Public Repositories (10):

   📂 octocat (6 public repos):
      • octocat/awesome-project (admin)
      • octocat/tutorial-code (admin)
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

## Integration Examples

### Python Script

```python
import subprocess
import json

def analyze_github_token(token):
    """Analyze a GitHub token and return structured data."""
    result = subprocess.run([
        'python', 'gimmepatz.py', token, '--json'
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        return None

# Usage
token_data = analyze_github_token('ghp_your_token_here')
if token_data and token_data['token_valid']:
    print(f"Token belongs to: {token_data['user_info']['login']}")
    print(f"Total repositories: {token_data['summary']['total_repos']}")
    print(f"Private repositories: {token_data['summary']['private_count']}")
```

### Bash Script

```bash
#!/bin/bash

TOKEN="ghp_your_token_here"
OUTPUT=$(python gimmepatz.py "$TOKEN" --json)

# Extract information using jq
if command -v jq &> /dev/null; then
    PRIVATE_COUNT=$(echo "$OUTPUT" | jq '.summary.private_count')
    PUBLIC_COUNT=$(echo "$OUTPUT" | jq '.summary.public_count')
    USER=$(echo "$OUTPUT" | jq -r '.user_info.login')
    
    echo "User: $USER"
    echo "Private repos: $PRIVATE_COUNT"
    echo "Public repos: $PUBLIC_COUNT"
else
    echo "jq not installed. Install with: apt-get install jq"
fi
```

```bash
#!/bin/bash
python3 gimmepatz.py 
```

## Token Scopes Reference

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

## Security Best Practices

1. **Never commit tokens to version control**
2. **Use environment variables for tokens**
   ```bash
   export GITHUB_TOKEN="your_token_here"
   python gimmepatz.py "$GITHUB_TOKEN"
   ```
3. **Regularly audit your tokens** using this tool
4. **Use minimal required scopes** for each token
5. **Set expiration dates** on your tokens when possible
6. **Rotate tokens regularly** as part of security hygiene

## Troubleshooting

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v1.0.0
- Initial release
- Token validation and scope analysis
- Repository discovery with privacy separation
- JSON output for automation
- Organization repository support
- ASCII art branding

---

**Made with ❤️ for GitHub security and token management**
