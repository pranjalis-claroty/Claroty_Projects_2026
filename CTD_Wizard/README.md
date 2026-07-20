# CTD Best Practice Wizard

An automated post-installation configuration assessment and troubleshooting script designed for Claroty CTD deployments. This tool operates via the CTD REST API to pull environment configurations and evaluate them against operational baselines—ideal for secure or remote Federal POV environments.

## Features
- **Automated Authentication**: Securely exchanges credentials for a dynamic JWT bearer token.
- **License Compliance Check**: Audits expiration states and deployment licensing parameters.
- **Zone & Subnet Topology Mapping**: Enumerates virtual zones to identify unclassified network segments.
- **System Health Insights**: Examines passive/active sensor monitoring connectivity and health metrics.

## Prerequisites
- Python 3.8 or higher
- Network access to the target Claroty CTD instance

## Quick Start
1. Clone this repository to your local VS Code workspace:
   ```bash
   git clone <your-github-repo-url>
   cd ctd-best-practice-wizard
