# Changelog

All notable changes to kotlin-security-scanner are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-06-23

First public release on Maven Central:
`io.github.jasminguberinic:scanner-{core,spring-boot,quarkus,dropwizard,ktor,micronaut,all}:0.2.0`.

> Note: an earlier `0.1.0` was prepared but never published to Maven Central (the deployment
> was validated but not released), so `0.2.0` is the first version users can actually depend on.

### Highlights

- **201 security rules** across 6 modules, mapped to the OWASP Top 10 and tagged with CWE IDs.
- **Active by default** — every rule fires on the first `./gradlew detekt` with no per-rule
  configuration. Disable any rule with `active: false` in `detekt.yml`.
- **1262 tests**, every rule verified end-to-end against intentionally vulnerable fixtures plus a
  companion safe-code fixture proving zero false positives.

### Added

- New `scanner-micronaut` module (Micronaut Security / config / client rules).
- Framework-agnostic rules consolidated into `scanner-core` so they fire on every framework:
  JAX-RS/Micronaut open redirect, CORS wildcard origin, hardcoded JWT secret.
- Secret scanning: Google API key, Slack token, GitHub token, Stripe live secret key,
  hardcoded JWT bearer token, JDBC URL credentials.
- Additional core rules: insecure `SSLContext` protocol, Zip Slip, regex injection (ReDoS),
  log forging (CWE-117), world-accessible file permissions, predictable temp files.
- Spring Boot: clickjacking (`frameOptions disable`), MIME-sniffing (`contentTypeOptions disable`),
  session-fixation `none()`, CSRF `ignoringRequestMatchers`.
- Ktor: `respondFile` path traversal, `developmentMode = true`, permissive CORS `anyHeader()`.
- Micronaut: anonymous access on state-changing endpoints, insecure cookie (`secure(false)`).
- Quarkus: `@CacheResult` on a secured method (cross-user cache leak).
- Injection rules now detect dynamic string **concatenation** (`"(uid=" + name + ")"`) in addition
  to interpolation (LDAP, XPath, Panache, Quarkus path-param).

### Fixed

- **Rules now activate by default for published consumers.** Detekt leaves unconfigured rules
  inactive; previously a project that simply added the plugin got zero findings. Rules are now on
  out of the box (still disable-able via config).
- **Properties-file rules** (Spring/Quarkus/Dropwizard config scanners) report at the real
  `application.properties` line instead of line 1 of an arbitrary Kotlin file, and exactly once
  instead of once per Kotlin file in the module.
- Pre-release correctness audit of all 201 rules: eliminated ~45 false-positive, false-negative,
  and dead-detection defects (fully-qualified-name receivers, substring over-matching, wrong
  argument indices, Spring `${prop:default}` vs bash `:-` syntax). No crash bugs found.

[0.2.0]: https://github.com/JasminGuberinic/kotlin-security-scanner/releases/tag/v0.2.0
