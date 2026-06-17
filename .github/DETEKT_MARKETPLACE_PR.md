# Detekt Marketplace PR

Add this entry to `website/src/data/marketplace.js` in the `detekt/detekt` repo,
in alphabetical order by title (between "K" entries).

## Entry to add

```javascript
  {
    title: "Kotlin Security Scanner",
    description:
      "68 OWASP Top 10 rules for Kotlin Spring Boot, Quarkus & Dropwizard. Catches what FindSecBugs misses.",
    repo: "https://github.com/JasminGuberinic/kotlin-security-scanner",
    ruleset: "security-core",
    rules: [
      "WeakCipherMode",
      "WeakHashAlgorithm",
      "TrustAllCerts",
      "HardcodedIv",
      "WeakRsaKey",
      "JwtNoneAlgorithm",
      "JwtWeakSecret",
      "UnsafeCryptoPaddingOracle",
      "InsecurePasswordStorage",
      "SqlInjection",
      "LdapInjection",
      "JndiInjection",
      "XpathInjection",
      "ReflectionInjection",
      "PathTraversal",
      "CommandInjection",
      "XxeInjection",
      "GroovyScriptInjection",
      "RegexDenialOfService",
      "HardcodedCredentials",
      "InsecureRandom",
      "InsecureDeserialization",
      "JacksonUnsafeDeserialization",
      "XmlMapperUnsafe",
      "SensitiveDataLogging",
      "Ssrf",
    ],
    usesTypeResolution: false,
    tags: ["ruleset"],
  },
```

## PR description

**Title:** Add kotlin-security-scanner — 68 OWASP Top 10 rules for Kotlin backends

**Body:**
```
## What this adds

[kotlin-security-scanner](https://github.com/JasminGuberinic/kotlin-security-scanner)
is a Detekt plugin with 68 OWASP Top 10 rules specifically for Kotlin Spring Boot,
Quarkus, and Dropwizard applications.

### Why it belongs here

The project covers patterns that bytecode tools (FindSecBugs, SonarQube free tier) 
structurally cannot detect:

- `suspend fun` with `@PreAuthorize` — coroutine desugaring silently drops security 
  context ([Spring Security #10810](https://github.com/spring-projects/spring-security/issues/10810))
- Kotlin PSI nodes: `KtStringTemplateExpression`, `KtDotQualifiedExpression`
- `let`/`run`/`apply` taint propagation
- Properties-file scanning (`application.properties` actuator exposure, SMTP config, 
  OIDC misconfiguration)

### Modules

| Module | Rules | Frameworks |
|---|---|---|
| `scanner-core` | 26 | Any Kotlin project |
| `scanner-spring-boot` | 18 | Spring Boot / Spring Security / Spring WebFlux |
| `scanner-quarkus` | 8 | Quarkus / MicroProfile / JAX-RS |
| `scanner-dropwizard` | 6 | Dropwizard / JAX-RS |

### Coverage

Full OWASP A01–A10 coverage including A06 (ReDoS) — 68 rules total.
All rules have positive, negative, and isolation tests.
```

## How to submit

1. Fork `detekt/detekt`
2. Add the entry above to `website/src/data/marketplace.js` (alphabetical order by title)
3. Open PR with the description above
