# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously at CERT-X-GEN. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Please DO NOT file a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by emailing:

**security@bugb.io** 

### What to Include

Please include the following in your report:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Assessment**: We will investigate and validate the vulnerability within 7 days
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to release a fix within 30 days for critical issues
- **Credit**: With your permission, we will credit you in our release notes

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized concerning any applicable anti-hacking laws
- Exempt from DMCA restrictions
- Conducted in good faith

We will not pursue legal action against researchers who:

- Follow this policy
- Make good faith efforts to avoid privacy violations and data destruction
- Avoid disruption of our services
- Give us reasonable time to address issues before public disclosure

## Security Best Practices for Users

When using CERT-X-GEN:

1. **Template Sources**: Only use templates from trusted sources
2. **Sandboxing**: Enable sandbox mode when running untrusted templates
3. **API Keys**: Store API keys in environment variables, not in config files
4. **Network**: Use proxies when scanning sensitive targets
5. **Updates**: Keep CERT-X-GEN and templates updated

## Template Security

CERT-X-GEN executes code from templates in multiple languages. Please:

- Review templates before execution
- Use `--safe` mode for production systems
- Validate template signatures when available
- Report malicious templates immediately

## Contact

For general security questions (non-vulnerabilities):
- Open a GitHub Discussion
- Tag your post with `security`

For vulnerability reports:
- Email: security@bugb.io

Thank you for helping keep CERT-X-GEN and its users safe!
