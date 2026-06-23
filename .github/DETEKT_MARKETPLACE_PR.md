# Detekt Marketplace PR

Add this entry to `website/src/data/marketplace.js` in the `detekt/detekt` repo,
in alphabetical order by title (between "K" entries).

Current release: **v0.2.0 — 201 rules across 6 rulesets, on Maven Central.**

## Entry to add

```javascript
  {
    title: "Kotlin Security Scanner",
    description:
      "201 OWASP Top 10 rules for Kotlin Spring Boot, Quarkus, Dropwizard, Ktor & Micronaut. Active by default. Catches what FindSecBugs misses.",
    repo: "https://github.com/JasminGuberinic/kotlin-security-scanner",
    ruleset: "security-core",
    rules: [
      "JaxrsOpenRedirect",
      "WeakCipherMode",
      "WeakHashAlgorithm",
      "TrustAllCerts",
      "TrustAllHostnames",
      "HardcodedIv",
      "HardcodedAesKey",
      "HardcodedPrivateKey",
      "WeakRsaKey",
      "InsecureSslContext",
      "JwtNoneAlgorithm",
      "JwtWeakSecret",
      "UnsafeCryptoPaddingOracle",
      "InsecurePasswordStorage",
      "InsecureRandomSeed",
      "SqlInjection",
      "LdapInjection",
      "JndiInjection",
      "XpathInjection",
      "ReflectionInjection",
      "PathTraversal",
      "CommandInjection",
      "XxeInjection",
      "GroovyScriptInjection",
      "ZipSlip",
      "RegexDenialOfService",
      "RegexInjection",
      "CorsWildcardOrigins",
      "InsecureFilePermissions",
      "PredictableTempFile",
      "HardcodedCredentials",
      "HardcodedAwsCredentials",
      "GoogleApiKey",
      "SlackToken",
      "GitHubToken",
      "StripeSecretKey",
      "HardcodedJwtToken",
      "HardcodedJdbcCredentials",
      "InsecureRandom",
      "InsecureDeserialization",
      "JacksonUnsafeDeserialization",
      "XmlMapperUnsafe",
      "KotlinxSerializationSensitiveField",
      "SensitiveDataLogging",
      "LogForging",
      "Ssrf",
    ],
    usesTypeResolution: false,
    tags: ["ruleset"],
  },
```

> The list above is the `security-core` ruleset (46 framework-agnostic rules). The plugin also
> ships `security-spring-boot`, `security-quarkus`, `security-dropwizard`, `security-ktor`, and
> `security-micronaut` rulesets — 201 rules total.

## PR description

**Title:** Add kotlin-security-scanner — 201 OWASP Top 10 rules for Kotlin backends

**Body:**
```
## What this adds

[kotlin-security-scanner](https://github.com/JasminGuberinic/kotlin-security-scanner)
is a Detekt plugin with 201 OWASP Top 10 rules for Kotlin Spring Boot, Quarkus,
Dropwizard, Ktor, and Micronaut applications. It's on Maven Central:

    detektPlugins("io.github.jasminguberinic:scanner-all:0.2.0")

Rules are active by default and CWE-tagged; findings appear on the first run with no
per-rule config.

### Why it belongs here

The project covers patterns that bytecode tools (FindSecBugs, SonarQube free tier)
structurally cannot detect:

- `suspend fun` with `@PreAuthorize` — coroutine desugaring silently drops security
  context ([Spring Security #10810](https://github.com/spring-projects/spring-security/issues/10810))
- Kotlin PSI nodes: `KtStringTemplateExpression`, `KtDotQualifiedExpression`
- string template + concatenation injection (SQL/LDAP/XPath/Panache)
- properties-file scanning (`application.properties` actuator exposure, SMTP config,
  Quarkus OIDC misconfiguration)
- hardcoded cloud secrets: Google / Slack / GitHub / Stripe / JWT / JDBC

### Modules

| Module | Rules | Frameworks |
|---|---|---|
| `scanner-core` | 46 | Any Kotlin project |
| `scanner-spring-boot` | 55 | Spring Boot / Spring Security / Spring WebFlux |
| `scanner-quarkus` | 39 | Quarkus / MicroProfile / JAX-RS |
| `scanner-dropwizard` | 14 | Dropwizard / JAX-RS |
| `scanner-ktor` | 34 | Ktor |
| `scanner-micronaut` | 13 | Micronaut |

### Coverage & quality

Full OWASP A01–A10 coverage — 201 rules total. Every rule has positive, negative, and
isolation tests (1262 tests), and is verified end-to-end against vulnerable fixtures with
a safe-code fixture proving zero false positives.
```

## How to submit

1. Fork `detekt/detekt`
2. Add the entry above to `website/src/data/marketplace.js` (alphabetical order by title)
3. Open PR with the description above
