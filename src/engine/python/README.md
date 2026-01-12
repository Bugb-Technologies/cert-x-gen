# Python Template Engine

The Python template engine executes security checks written in Python scripts.

## Features

- **Full Python Runtime**: Execute arbitrary Python code for complex checks
- **Network Access**: Make HTTP requests, TCP connections, etc.
- **Custom Logic**: Implement complex vulnerability detection logic
- **Library Support**: Use Python libraries for specialized checks

## Supported Protocols

- All protocols (Python has full network access)

## Template Structure

Python templates are `.py` files with metadata comments at the top:

```python
"""
id: python-template-id
name: Python Template Name
severity: high
description: Template description
tags:
  - python
  - custom
"""

def execute(target, context):
    """
    Execute the security check.
    
    Args:
        target: Target object with address, url, etc.
        context: Execution context with config, variables, etc.
    
    Returns:
        List of Finding objects
    """
    findings = []
    
    # Your detection logic here
    
    return findings
```

## Files

- `mod.rs` - Engine implementation and Python runtime integration

## Future Enhancements

- Python virtual environment support
- Dependency management
- Sandboxing for untrusted templates
- Performance optimization
