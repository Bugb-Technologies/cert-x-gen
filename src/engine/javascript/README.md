# JavaScript Template Engine

The JavaScript template engine executes security checks written in JavaScript/Node.js.

## Features

- **Node.js Runtime**: Execute JavaScript code with Node.js
- **Async/Await Support**: Modern async JavaScript patterns
- **NPM Packages**: Use npm packages for specialized checks
- **JSON Handling**: Native JSON parsing and manipulation

## Supported Protocols

- All protocols (JavaScript has full network access via Node.js)

## Template Structure

JavaScript templates are `.js` files with metadata comments:

```javascript
/**
 * id: javascript-template-id
 * name: JavaScript Template Name
 * severity: medium
 * description: Template description
 * tags:
 *   - javascript
 *   - nodejs
 */

async function execute(target, context) {
    const findings = [];
    
    // Your detection logic here
    // Can use fetch, axios, etc.
    
    return findings;
}

module.exports = { execute };
```

## Files

- `mod.rs` - Engine implementation and Node.js runtime integration

## Future Enhancements

- TypeScript support
- ESM module support
- Package.json dependency management
- Deno runtime option
