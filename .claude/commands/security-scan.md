# Security Scan

Run the Detekt security scanner and interpret the results.

## Usage

```
/security-scan [path/to/target]
```

If a path is provided, configure detekt `source` to point there.
Default scans `src/main/kotlin`.

---

## Steps

**1. Run the scan:**

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew detekt
```

**2. Parse the output:**

Group findings by OWASP category:
- `[HardcodedCredentials]` → A07
- `[SqlInjection]` → A03
- `[WeakCipherMode]` → A02
- `[PathTraversal]` → A03
- `[SpringCsrfDisabled]` → A05
- `[PermissiveCors]` → A05
- `[InsecureRandom]` → A07
- `[SensitiveDataLogging]` → A09
- `[MissingAuthorization]` → A01
- `[Ssrf]` → A10
- `[ForbiddenImport]` / `[ForbiddenMethodCall]` → varies (see detekt.yml)

**3. Prioritize by severity:**

Report findings in this order: Security → Warning → Style

**4. For each finding, explain:**
- What the vulnerability is
- Why it is dangerous (real-world impact)
- How to fix it (concrete code example)

**5. Produce a summary table:**

| File | Line | Rule | OWASP | Fix |
|------|------|------|-------|-----|
| ... | ... | ... | ... | ... |

**6. If the HTML report exists:**
Open `build/reports/detekt/detekt.html` and reference it for full context.

---

## Interpreting `VulnerableExamples.kt` findings

`src/main/kotlin/com/jasmin/security/example/VulnerableExamples.kt` is
intentional demo code. Its findings show the scanner is working — do NOT
treat them as production vulnerabilities.
