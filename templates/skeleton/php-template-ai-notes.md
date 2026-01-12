# CERT-X-GEN PHP Template Skeleton – AI Notes

## Purpose
- **Role**: Starting point for PHP CERT-X-GEN code templates.
- **Contract**: Must follow `SKELETON_CONTRACT.md` for metadata, input, ports, output, and errors.
- **Companion**: This file explains how to use `php-template-skeleton.php` correctly.

If you are an AI or code generator, treat this file as authoritative guidance for PHP templates.

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
**Do not** use `ADD_PORTS` / `OVERRIDE_PORTS` as a generic scan list.

## Where to put custom logic
- Keep intact:
  - CLI/argument parsing.
  - Environment variable handling and `$this->context` population.
  - JSON encoding and any marker fields.
- Implement detection inside the main execution methods that operate on the single host+port, as indicated in the skeleton.
- Use existing HTTP/network helpers that the skeleton already defines.

## Output expectations
- Always write valid JSON to **stdout**.
- Follow the JSON structure from `php-template-skeleton.php` and `SKELETON_CONTRACT.md`:
  - array of findings arrays/objects with required fields.
  - preserve engine marker fields.
- Send logs and errors to **stderr**, not stdout.
- An empty findings array is valid.

## Good patterns for PHP
- Use the cURL-based helpers or other built-in mechanisms already wired into the skeleton.
- Keep vulnerability checks focused and simple.

## Things to avoid
- Modifying env/CLI behavior or JSON layout.
- Removing or renaming markers.
- Implementing generic host/port scanners.
- Inventing unsupported env vars or output formats.
