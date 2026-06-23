---
name: Request a security rule
about: Suggest a new vulnerability pattern for the scanner to detect
title: "[Rule] <short name>"
labels: [rule-request]
---

**Vulnerability / weakness**
<!-- What insecure pattern should be detected? -->

**OWASP / CWE / FindSecBugs reference**
<!-- e.g. OWASP A03, CWE-89, SQL_INJECTION -->

**Framework**
<!-- Any Kotlin (core) | Spring Boot | Quarkus | Dropwizard | Ktor | Micronaut -->

**Non-compliant example**

```kotlin
// code that SHOULD be flagged
```

**Compliant example**

```kotlin
// the safe equivalent that must NOT be flagged
```

**Notes**
<!-- false-positive risks, links, prior art -->
