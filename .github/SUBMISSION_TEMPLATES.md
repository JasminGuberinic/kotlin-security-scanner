# Submission Templates for Discoverability

Current release: **v0.2.0 — 201 rules, 6 modules, on Maven Central.**
Install: `detektPlugins("io.github.jasminguberinic:scanner-all:0.2.0")` (or pick per-framework modules).

## 1. analysis-tools.dev

URL: https://analysis-tools.dev/submit

Fill in the form with:
- **Name:** kotlin-security-scanner
- **Categories:** Security, Static Analysis
- **Languages:** Kotlin
- **Homepage:** https://github.com/JasminGuberinic/kotlin-security-scanner
- **Description:**
  > Detekt plugin with 201 OWASP Top 10 security rules for Kotlin — Spring Boot, Quarkus,
  > Dropwizard, Ktor, and Micronaut. Catches coroutine security-context loss, JWT attacks,
  > SQL/LDAP/JNDI injection, XXE, Zip Slip, insecure crypto, ReDoS, SSRF, hardcoded cloud
  > secrets (Google/Slack/GitHub/Stripe), and more — patterns that bytecode tools like
  > FindSecBugs cannot detect. Active by default, CWE-tagged, SARIF output, zero infra.
- **License:** Apache-2.0
- **Pricing:** Free / Open Source

---

## 2. awesome-kotlin PR

Repo: https://github.com/KotlinBy/awesome-kotlin

Add to section **Libraries/Frameworks > Security**:

```markdown
* [kotlin-security-scanner](https://github.com/JasminGuberinic/kotlin-security-scanner) -
  Detekt plugin with 201 OWASP Top 10 security rules for Spring Boot, Quarkus, Dropwizard,
  Ktor, and Micronaut. Active by default, CWE-tagged, on Maven Central.
```

Steps:
1. Fork `KotlinBy/awesome-kotlin`
2. Edit `README.md` — find the Security section under Libraries/Frameworks
3. Add the entry above in alphabetical order
4. PR title: `Add kotlin-security-scanner — OWASP Top 10 Detekt rules`

---

## 3. Kotlin Weekly newsletter

URL: https://kotlinweekly.net/submit

**Subject:** kotlin-security-scanner — 201 OWASP Top 10 rules as a Detekt plugin

**Body:**
```
Hi,

I'd like to submit kotlin-security-scanner for consideration in Kotlin Weekly.

https://github.com/JasminGuberinic/kotlin-security-scanner

It's a Detekt plugin with 201 OWASP Top 10 security rules for Kotlin backends —
Spring Boot, Quarkus, Dropwizard, Ktor, and Micronaut. It's on Maven Central:

    detektPlugins("io.github.jasminguberinic:scanner-all:0.2.0")

Rules are active by default, so findings appear on the first `./gradlew detekt` with no
per-rule config. Every rule is CWE-tagged and verified end-to-end (1262 tests, plus a
safe-code fixture proving zero false positives).

The key differentiator is that it detects patterns that bytecode tools (FindSecBugs,
SonarQube) cannot — because they operate on bytecode, not Kotlin's PSI tree:

• suspend fun + @PreAuthorize — Spring Security silently drops the security context
  due to coroutine proxy desugaring
• Kotlin string template + concatenation injection patterns
• application.properties scanning: actuator wildcard exposure, SMTP cleartext,
  Quarkus OIDC misconfiguration
• JWT algorithm=none, AES/CBC padding oracle, ReDoS, Zip Slip
• hardcoded cloud secrets: Google / Slack / GitHub / Stripe / JWT / JDBC

It runs as a Gradle plugin, offline, on every build — zero infra required.
SARIF output integrates with GitHub Code Scanning for inline PR annotations.

Thanks for considering it!
```

---

## 4. OWASP Source Code Analysis Tools page

URL: https://owasp.org/www-community/Source_Code_Analysis_Tools (edit on GitHub)

Repo: https://github.com/OWASP/www-community

File: `pages/Source_Code_Analysis_Tools.md`

Add under "Free/Open Source Tools" table, Kotlin section:

```markdown
| [kotlin-security-scanner](https://github.com/JasminGuberinic/kotlin-security-scanner) | Kotlin |
Detekt plugin, 201 OWASP Top 10 rules, Spring Boot/Quarkus/Dropwizard/Ktor/Micronaut,
catches Kotlin-specific patterns bytecode tools miss | Apache 2.0 |
```
