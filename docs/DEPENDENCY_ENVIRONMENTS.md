# Dependency environments

This guide now lives at **<https://docs.bugb.io/cxg/guides/manage-dependency-environments/>**.

What `cxg sandbox` does, the init state bug and the path around it, and why none of it is a security boundary.

It moved because the documentation site is generated against a released
binary and its commands are verified by running them, which a hand-written
file in this repository cannot promise. Keeping both meant one of them was
always wrong.

| Page | |
| --- | --- |
| Manage template dependency environments | <https://docs.bugb.io/cxg/guides/manage-dependency-environments/> |
| Template trust model | <https://docs.bugb.io/cxg/concepts/template-trust-model/> |
| cxg sandbox reference | <https://docs.bugb.io/cxg/reference/cli/templates/#cxg-sandbox> |

Architecture and contributor documentation stays in this repository. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) if you are changing cxg
itself rather than using it.
