# CERT-X-GEN: Pre-Release TODO

## 🔴 Before Going Public

### Code Quality
- [ ] Fix 104 clippy warnings (tracked categories below)
- [ ] Re-enable strict clippy in CI (`-D warnings`)
- [ ] Add more unit tests (current coverage is minimal)
- [ ] Add integration tests for all 12 language engines

### Clippy Warnings Breakdown
| Category | Count | Priority |
|----------|-------|----------|
| Collapsible if statements | ~8 | Low |
| Regex compiled in loop | ~5 | Medium (perf) |
| Empty line after doc comment | ~3 | Low |
| Redundant closures | ~3 | Low |
| Unnecessary casts | ~2 | Low |
| Other style issues | ~83 | Low |

### Documentation
- [ ] Add logo/banner image to README
- [ ] Create GitHub Pages docs site (optional)
- [ ] Add more inline code documentation
- [ ] Write "Getting Started" tutorial

### Templates
- [ ] Add 5-10 showcase templates demonstrating polyglot power
- [ ] Ensure all skeleton templates are well-documented
- [ ] Add templates for popular CVEs

### Repository
- [ ] Add GitHub topics/tags
- [ ] Configure Dependabot for dependency updates
- [ ] Add CHANGELOG.md
- [ ] Set up release workflow (goreleaser or manual)

### Testing
- [ ] Test on fresh Linux VM
- [ ] Test on fresh macOS
- [ ] Verify all 12 language engines work
- [ ] Test AI generation with Ollama

---

## 🟡 Nice to Have

- [ ] Homebrew formula
- [ ] Docker image
- [ ] VS Code extension for template development
- [ ] Web-based template playground

---

## 🟢 Launch Checklist

- [ ] All CI checks pass
- [ ] README renders correctly
- [ ] License is correct
- [ ] Security policy is in place
- [ ] No secrets in codebase
- [ ] Flip visibility to PUBLIC
- [ ] Announce on Twitter/X
- [ ] Post on Reddit (r/netsec, r/rust)
- [ ] Submit to Hacker News

---

*Last updated: January 2026*
