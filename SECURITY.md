# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2026.x  | :white_check_mark: |
| < 2026  | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Sovra, please report it responsibly.

### How to Report

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Use GitHub's private vulnerability reporting
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We aim to acknowledge receipt within 7 days
- **Initial Assessment**: Within 30 days, we will provide an initial assessment
- **Resolution Timeline**: We aim to resolve critical vulnerabilities within 90 days
- **Disclosure**: We will coordinate with you on public disclosure timing

### Security Measures

This project implements the following security practices:

- **Dependency Scanning**: Dependabot monitors for vulnerable dependencies
- **License Compliance**: FOSSA scans for license policy violations

## Security Best Practices for Users

When deploying Sovra:

1. Keep dependencies up to date
2. Use environment variables for sensitive configuration
3. Run with least-privilege permissions
4. Enable audit logging in production
5. Review and customize policies for your environment

