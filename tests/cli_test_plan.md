# CXG CLI Test Plan

## Test Categories

### 1. Global Options
- [ ] `cxg --help`
- [ ] `cxg -h`
- [ ] `cxg --version`
- [ ] `cxg -V`
- [ ] `cxg --ut` (update templates)
- [ ] `cxg -v` (verbose level 1)
- [ ] `cxg -vv` (verbose level 2)
- [ ] `cxg -vvv` (verbose level 3)
- [ ] `cxg --no-color`

### 2. Template Management (`cxg template`)
- [ ] `cxg template list`
- [ ] `cxg template list --language python`
- [ ] `cxg template list --language rust`
- [ ] `cxg template list --language yaml`
- [ ] `cxg template list --severity high`
- [ ] `cxg template list --tags database`
- [ ] `cxg template update`
- [ ] `cxg template validate <path>`
- [ ] `cxg template info <template-id>`
- [ ] `cxg template create --id test --language python`
- [ ] `cxg template test --template <id> --target <host>`

### 3. Search (`cxg search`)
- [ ] `cxg search --query "redis"`
- [ ] `cxg search --language python`
- [ ] `cxg search --severity critical`
- [ ] `cxg search --tags database`
- [ ] `cxg search --format json`
- [ ] `cxg search --format csv`
- [ ] `cxg search --ids-only`
- [ ] `cxg search --stats`

### 4. Scan (`cxg scan`)
- [ ] `cxg scan --scope <target>` (basic)
- [ ] `cxg scan --scope <target> --ports 80,443`
- [ ] `cxg scan --scope <target> --top-ports 100`
- [ ] `cxg scan --scope <target> --templates <id>`
- [ ] `cxg scan --scope <target> --template-language python`
- [ ] `cxg scan --scope <target> --severity high`
- [ ] `cxg scan --scope <target> --tags database`
- [ ] `cxg scan --scope <target> -v` (verbose)
- [ ] `cxg scan --scope <target> --output-format json`

### 5. AI Generation (`cxg ai`)
- [ ] `cxg ai --help`
- [ ] `cxg ai generate --help`
- [ ] `cxg ai generate --description "..." --language python`

### 6. Config (`cxg config`)
- [ ] `cxg config --help`
- [ ] `cxg config generate`

### 7. Template Validation (All Languages)
For each template in ~/.cert-x-gen/templates/official/templates/:
- [ ] Validate syntax
- [ ] Test execution against safe target

## Test Targets

For safe testing, we can use:
1. **localhost** - Local services (Redis, etc. if running)
2. **scanme.nmap.org** - Nmap's public test server
3. **httpbin.org** - HTTP testing service
4. **testphp.vulnweb.com** - Acunetix test site (for web vulns)

## Template Test Matrix

| Language | Count | Validation | Execution |
|----------|-------|------------|-----------|
| YAML     | 24    | [ ]        | [ ]       |
| Python   | 12    | [ ]        | [ ]       |
| Shell    | 7     | [ ]        | [ ]       |
| Rust     | 5     | [ ]        | [ ]       |
| JavaScript | 4   | [ ]        | [ ]       |
| C        | 4     | [ ]        | [ ]       |
| Go       | 1     | [ ]        | [ ]       |
| C++      | 1     | [ ]        | [ ]       |
| Java     | 1     | [ ]        | [ ]       |
| Perl     | 1     | [ ]        | [ ]       |
| PHP      | 1     | [ ]        | [ ]       |
| Ruby     | 1     | [ ]        | [ ]       |
