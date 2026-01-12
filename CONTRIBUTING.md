# Contributing to CERT-X-GEN

Thank you for your interest in contributing to CERT-X-GEN! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and collaborative environment.

## Getting Started

### Prerequisites

- Rust 1.70 or higher
- Git
- Basic understanding of security testing concepts

### Development Setup

1. **Fork and clone the repository**

```bash
git clone https://github.com/your-username/cert-x-gen.git
cd cert-x-gen
```

2. **Set up development environment**

```bash
make setup
```

3. **Build the project**

```bash
make build
```

4. **Run tests**

```bash
make test
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Changes

- Write clean, idiomatic Rust code
- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all checks
make check

# Run tests
make test

# Run clippy
make lint

# Format code
make fmt
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature"
# or
git commit -m "fix: resolve issue with..."
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Code Style Guidelines

### Rust Code

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting: `make fmt`
- Pass `clippy` lints: `make lint`
- Write comprehensive documentation comments
- Add examples where appropriate

### Documentation

- Document all public APIs
- Include examples in doc comments
- Keep README.md up to date
- Add inline comments for complex logic

### Testing

- Write unit tests for new functions
- Add integration tests for features
- Maintain >80% code coverage
- Test error conditions

Example:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        let result = my_function();
        assert_eq!(result, expected_value);
    }

    #[tokio::test]
    async fn test_async_feature() {
        let result = my_async_function().await;
        assert!(result.is_ok());
    }
}
```

## Template Contribution

### Creating a New Template

1. **Choose the appropriate language**
   - YAML for simple declarative checks
   - Python for complex logic
   - Rust for performance-critical templates
   - Shell for system-level checks

2. **Create template file**

```bash
# YAML template
templates/yaml/category/your-template.yaml

# Python template
templates/python/category/your-template.py
```

3. **Include comprehensive metadata**

```yaml
id: CVE-YYYY-XXXXX
name: "Descriptive Name"
author:
  name: "Your Name"
  email: "your.email@example.com"
severity: critical|high|medium|low|info
description: "Detailed description"
tags:
  - relevant
  - tags
```

4. **Test the template**

```bash
cert-x-gen template test your-template.yaml --target test-target.com
```

5. **Validate the template**

```bash
cert-x-gen template validate your-template.yaml
```

### Template Quality Standards

- **Accuracy**: No false positives
- **Performance**: Execute in <30 seconds
- **Documentation**: Clear description and remediation
- **References**: Include CVE/CWE IDs and references
- **Testing**: Test against vulnerable and patched systems

## Pull Request Guidelines

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass (`make test`)
- [ ] Lints pass (`make lint`)
- [ ] Code is formatted (`make fmt`)
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] PR description is clear and complete

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Tests pass
- [ ] Lints pass
- [ ] Documentation updated
```

## Review Process

1. Automated checks run (CI/CD)
2. Code review by maintainers
3. Address feedback
4. Approval and merge

## Reporting Issues

### Bug Reports

Include:
- CERT-X-GEN version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative approaches considered
- Implementation ideas

## Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email: security@cert-x-gen.io

Include:
- Vulnerability description
- Steps to reproduce
- Impact assessment
- Suggested fix (if available)

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

## Questions?

- Open a discussion on GitHub
- Join our Discord: https://discord.gg/cert-x-gen
- Email: team@cert-x-gen.io

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md
- Release notes
- Project website

Thank you for contributing to CERT-X-GEN! 🚀
