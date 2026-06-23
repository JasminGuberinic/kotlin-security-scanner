# Security Policy

## Reporting a vulnerability in the scanner

If you find a security issue **in this tool itself** (for example, a way to make the
analyzer crash, hang, or execute code while scanning a project), please report it
privately — do not open a public issue.

- Use GitHub's [private vulnerability reporting](https://github.com/JasminGuberinic/kotlin-security-scanner/security/advisories/new), or
- email the maintainer at the address listed on the [GitHub profile](https://github.com/JasminGuberinic).

Please include the affected version, a minimal Kotlin snippet that triggers the issue,
and what you expected to happen. We aim to acknowledge reports within a few days.

## Supported versions

Fixes are published against the latest `0.x` release on Maven Central. Older versions are
not patched; upgrade to the current version.

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| < 0.2 | ❌ |

## Scope and disclaimer

This is a static analysis tool. Its findings are **advisory**: they highlight risky
patterns for human review, not proof of an exploitable vulnerability, and the absence of
findings is **not** a guarantee that code is secure. Always combine it with code review,
dependency scanning, and dynamic testing. Treat a clean scan as one signal among many.
