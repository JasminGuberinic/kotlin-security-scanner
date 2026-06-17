# Submission Templates for Discoverability

## 1. analysis-tools.dev

URL: https://analysis-tools.dev/submit

Fill in the form with:
- **Name:** kotlin-security-scanner
- **Categories:** Security, Static Analysis
- **Languages:** Kotlin
- **Homepage:** https://github.com/JasminGuberinic/kotlin-security-scanner
- **Description:**
  > Detekt plugin with 68 OWASP Top 10 security rules for Kotlin Spring Boot, Quarkus,
  > and Dropwizard applications. Catches coroutine security context loss, JWT attacks,
  > SQL/LDAP/JNDI injection, XXE, insecure crypto, ReDoS, SSRF, and more — patterns that
  > bytecode tools like FindSecBugs cannot detect.
- **License:** Apache-2.0
- **Pricing:** Free / Open Source

---

## 2. awesome-kotlin PR

Repo: https://github.com/KotlinBy/awesome-kotlin

Add to section **Libraries/Frameworks > Security**:

```markdown
* [kotlin-security-scanner](https://github.com/JasminGuberinic/kotlin-security-scanner) - 
  Detekt plugin with 68 OWASP Top 10 rules for Spring Boot, Quarkus, and Dropwizard
```

Steps:
1. Fork `KotlinBy/awesome-kotlin`
2. Edit `README.md` — find the Security section under Libraries/Frameworks
3. Add the entry above in alphabetical order
4. PR title: `Add kotlin-security-scanner — OWASP Top 10 Detekt rules`

---

## 3. Kotlin Weekly newsletter

URL: https://kotlinweekly.net/submit

**Subject:** kotlin-security-scanner — 68 OWASP Top 10 rules as a Detekt plugin

**Body:**
```
Hi,

I'd like to submit kotlin-security-scanner for consideration in Kotlin Weekly.

https://github.com/JasminGuberinic/kotlin-security-scanner

It's a Detekt plugin with 68 OWASP Top 10 security rules specifically for Kotlin
Spring Boot, Quarkus, and Dropwizard backends.

The key differentiator is that it detects patterns that bytecode tools (FindSecBugs, 
SonarQube) cannot — because they operate on bytecode, not Kotlin's PSI tree:

• suspend fun + @PreAuthorize — Spring Security silently drops the security context
  due to coroutine proxy desugaring (Spring Security issue #10810)
• Kotlin string template injection patterns
• application.properties scanning: actuator wildcard exposure, SMTP cleartext,
  Quarkus OIDC misconfiguration
• JWT algorithm=none attacks, AES/CBC padding oracle, ReDoS in Regex()

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
Detekt plugin, 68 OWASP Top 10 rules, Spring Boot/Quarkus/Dropwizard, catches coroutine patterns | 
Apache 2.0 |
```
