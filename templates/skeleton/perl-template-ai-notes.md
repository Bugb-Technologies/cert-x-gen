# CERT-X-GEN Perl Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for Perl CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `perl-template-skeleton.pl` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for Perl templates.

## Runtime contract (per run)
- **Single target per run**: The engine passes exactly one `host` + `port` per invocation.
- The engine sets environment variables (see `SKELETON_CONTRACT.md` for full details):
  - `CERT_X_GEN_TARGET_HOST`
  - `CERT_X_GEN_TARGET_PORT`
  - `CERT_X_GEN_MODE` (value `"engine"` when run from CERT-X-GEN)
  - Optional advanced hints (do not treat as a generic scan list):
    - `CERT_X_GEN_ADD_PORTS`
    - `CERT_X_GEN_OVERRIDE_PORTS`
  - `CERT_X_GEN_CONTEXT` – JSON string with additional context.

**Do not** implement your own target/port expansion.
**Do not** scan over `ADD_PORTS` / `OVERRIDE_PORTS` generically.

## Where to put custom logic
- Preserve:
  - CLI argument parsing.
  - Environment variable reading and `%context_data` handling.
  - JSON encoding and any marker fields.
- Implement detection logic in the main execution functions using the single host+port.
- Use the existing HTTP/network helpers wired into the skeleton.

## Output expectations
- Always print valid JSON to **stdout**.
- Match the JSON format from `perl-template-skeleton.pl` and `SKELETON_CONTRACT.md`:
  - arrayref of findings hashes with required keys.
  - any engine markers must be preserved.
- Logs and errors go to **stderr`, not stdout.
- An empty findings list is valid.

## Good patterns for Perl
- Use standard Perl modules (`LWP::UserAgent`, etc.) as already used by the skeleton.
- Keep detection logic small and focused.

## Things to avoid
- Changing env/CLI behavior or JSON structure.
- Removing or renaming markers.
- Implementing generic scanners over many hosts/ports.
- Inventing new env vars or JSON shapes outside `SKELETON_CONTRACT.md`.
