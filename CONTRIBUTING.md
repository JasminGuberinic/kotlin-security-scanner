# Contributing

Thanks for helping improve kotlin-security-scanner. Contributions of new rules, bug
fixes, and false-positive reports are all welcome.

## Build & test

Requires **JDK 21** (Kotlin 2.0.10 / Detekt 1.23.7 are incompatible with newer JDKs in
the Gradle DSL).

```bash
export JAVA_HOME=/path/to/jdk-21
./gradlew test            # all rule unit tests
./gradlew detekt          # self-scan
./gradlew :scanner-e2e:detekt   # end-to-end: every rule must fire on the fixtures
```

A change is ready when `./gradlew clean build` is green.

## Adding a rule

Rules live in the module that matches their scope:

| Scope | Module |
|---|---|
| Any Kotlin code (crypto, injection, secrets, …) | `scanner-core` |
| Spring Boot / Quarkus / Dropwizard / Ktor / Micronaut specific | the matching `scanner-<framework>` |

Steps:

1. Add detection patterns to `scanner-core/.../core/DetectionPatterns.kt` (single source of truth).
2. Create the rule class in the correct `a0X/` package, extending `SecurityRule`. Keep it to one
   `visit…` method plus small named predicates.
3. Add a CWE tag in `core/CweMapping.kt` and a fix hint in `core/RemediationHints.kt`.
4. Register the rule in the module's `*RuleSetProvider` **and** in `config/detekt/detekt.yml`.
5. Write a test class with **positive** (flagged), **negative** (safe equivalent, no false
   positive), and **isolation** (another rule's fixture produces nothing here) cases.
6. Add a fixture to the matching `scanner-e2e` `Vulnerable*App.kt` so the rule fires end-to-end,
   and ensure `SafeExamples.kt` stays at zero findings.

### Rule quality bar

- **No crashes:** access arguments with `firstOrNull()` / `as?`, never `!!` or unchecked indexing.
- **No false positives:** prefer precision over recall. Match call receivers with
  `substringAfterLast(".")` so fully-qualified names work; never key off a bare substring
  (`"author"` must not match `"auth"`).
- **Active by default:** `SecurityRule` already makes rules active out of the box — don't override.

## Reporting issues

- **False positive / false negative:** include the Kotlin snippet, the rule ID, and what you
  expected. These are the most valuable reports for a SAST tool.
- **Bug in the analyzer itself:** see [SECURITY.md](SECURITY.md).

PRs should keep `./gradlew test detekt` passing and reference the relevant OWASP / CWE / FindSecBugs ID.
