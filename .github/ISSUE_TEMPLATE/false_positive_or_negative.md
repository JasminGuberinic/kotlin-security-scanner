---
name: False positive / false negative
about: A rule fired on safe code, or missed a real vulnerability
title: "[FP/FN] <RuleId>: short description"
labels: [false-positive-or-negative]
---

**Rule ID:** <!-- e.g. SqlInjection, MicronautMissingSecured -->

**Type:** <!-- false positive (fired on safe code) | false negative (missed a vuln) -->

**Minimal Kotlin snippet**

```kotlin
// smallest code that reproduces it
```

**What happened**
<!-- e.g. "flagged this line" / "no finding on this line" -->

**What you expected**
<!-- e.g. "should not flag — input is validated" / "should flag — user input reaches the query" -->

**Environment**
- scanner version: <!-- e.g. 0.2.0 -->
- module(s): <!-- scanner-core / scanner-spring-boot / ... -->
- Detekt version:
- JDK:
