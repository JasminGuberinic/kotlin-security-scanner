# Rule Development Guide

How the rules are implemented, what they do, and the methodology for adding more
**without degrading quality**. Read this before writing a new rule.

---

## 1. How a rule works (end to end)

Detekt parses Kotlin into a **PSI syntax tree** and walks it. A rule hooks onto one kind
of node and says "when you see this pattern → report it".

Every rule has:

1. **A class** in an `a0X/` package (by OWASP category) that extends `SecurityRule`
   (which extends Detekt's `Rule`).
2. **An `Issue`** — `id`, `severity`, `description`, `debt`.
3. **A `visit…` method** Detekt calls for each matching node: `visitCallExpression`,
   `visitStringTemplateExpression`, `visitNamedFunction`, `visitClass`,
   `visitBinaryExpression`, …
4. **Detection logic** that inspects the node (callee name, arguments, annotations, string
   content) using patterns from `core/DetectionPatterns.kt` and helpers from `SecurityRule`
   (`rawValue()`, `hasInterpolation()`, `annotationNames()`, `isDynamicStringConcat()`,
   receiver via `parent as? KtDotQualifiedExpression`).
5. **`reportAt(node, message)`** when the bad pattern is found — this automatically appends
   the **CWE tag** (`CweMapping`) and a **fix hint** (`RemediationHints`) and emits a Detekt
   `CodeSmell` (shown in the console, IDE, SARIF, and CI).

### The 5 files a rule touches
- `scanner-<module>/.../a0X/XxxRule.kt` — the rule class
- the module's `*RuleSetProvider` — register it so Detekt loads it
- `config/detekt/detekt.yml` — add the rule so it's configurable
- `core/CweMapping.kt` + `core/RemediationHints.kt` — CWE tag + fix hint
- a test class (`a0X/XxxRuleTest.kt`) + an e2e fixture (`scanner-e2e/.../Vulnerable*App.kt`)

`SecurityRule.active` is overridden to default **true**, so rules fire out of the box; a user
can still disable any with `active: false` in `detekt.yml`.

---

## 2. The 5 rule archetypes (mental model)

Almost every rule is one of these:

| Archetype | Visit method | Example |
|---|---|---|
| **Dangerous call** | `visitCallExpression` | `Cipher.getInstance("DES")`, `SSLContext.getInstance("SSLv3")` |
| **String literal / regex** | `visitStringTemplateExpression` | secret detection (Stripe/Slack/AWS via a `DetectionPatterns` regex) |
| **Annotation presence/absence** | `visitNamedFunction` / `visitClass` | Micronaut `@Get` without `@Secured`; Spring `@GetMapping` without `@PreAuthorize` |
| **Assignment / binary expr** | `visitBinaryExpression` | `developmentMode = true`; string concatenation in SQL |
| **Config file** | `PropertiesSecurityRule.scanProperties` | `application.properties` actuator/OIDC/SMTP misconfig |

---

## 3. Two analysis modes (and the key limitation)

- **AST / PSI** (most rules) — pattern-match on the syntax tree, **no type resolution**.
  Consequences:
  - Compare call receivers with `substringAfterLast(".")` so fully-qualified names match.
  - **Precision over recall:** flag interpolation *and* concatenation, but NOT a bare variable
    (without dataflow we can't tell if it's tainted → flagging it would be a false positive).
- **Properties files** — `PropertiesSecurityRule` scans `application.properties`, reports at the
  real key line, exactly once per module (owner-file dedup; no static state, daemon-safe).

> **Biggest future leap is not "more rules" — it's enabling Detekt type resolution.** That unlocks
> dataflow/taint analysis and far more precise rules. It's an architectural step, not a count.

---

## 4. ⭐ The quality bar (non-negotiable)

A new rule is NOT done until all of these hold. **Quality beats quantity — one false positive is
worse than ten missing rules** (false positives make people disable the whole plugin).

- [ ] **No crashes.** Access arguments with `firstOrNull()` / `getOrNull()` / `as?`. Never `!!`
      or unchecked indexing (`valueArguments[0]`).
- [ ] **No false positives.** Prove it: a negative test with the safe equivalent, and the rule
      stays at **zero findings on `scanner-e2e/.../SafeExamples.kt`**.
- [ ] **FQN-tolerant.** Receiver/class checks use `substringAfterLast(".")` — never a bare
      substring (`"author"` must not match `"auth"`; tokenize on boundaries instead).
- [ ] **Catches the real form.** A positive test for the actual vulnerable pattern (and its
      common variants — interpolation *and* `+` concatenation where relevant).
- [ ] **Tests:** positive (flagged) + negative (safe) + isolation (another rule's fixture → zero
      findings here).
- [ ] **e2e:** a fixture in the matching `Vulnerable*App.kt` so the rule fires end-to-end.
- [ ] **Wired up:** registered in the provider + `detekt.yml`, with a CWE tag and a fix hint.
- [ ] **Active-by-default** still works and `active: false` still disables it.

After any batch, run the full lens: `./gradlew clean build` green, e2e shows every rule firing,
`SafeExamples.kt` at zero findings.

> Lesson learned: the 178→201 push added rules in large batches and a later audit found ~45
> false-positive / false-negative / dead-detection defects. Bulk addition hides bugs. Don't repeat it.

---

## 5. ⭐ Adding rules going forward (the sane cadence)

**Do NOT add 50 rules at once.** The healthy model:

- **Small, themed batches: ~5–15 rules per minor release** (0.3.0, 0.4.0…), each release with a
  coherent theme — e.g. "0.3.0: Spring WebFlux", "0.4.0: more crypto", "0.5.0: gRPC/Kafka".
- **One rule fully finished before the next** — rule + tests + e2e + CWE + hint + docs. Never leave
  a half-wired rule.
- **Pick rules purely by real-world value**, not to hit a number. The headline is already "200+",
  so growth should be about depth and filling genuine gaps. Prioritise by:
  - what shows up in real pentest / compliance reports,
  - FindSecBugs / SonarQube parity gaps,
  - user requests (GitHub issues),
  - the pre-researched backlog in `RULES_BACKLOG.md`.
- **Every batch passes the quality bar in §4.** Treat false positives as release blockers.
- Use the `/add-security-rule` skill for consistent scaffolding.
- Tie each batch to a semver release and a short CHANGELOG entry; one blog post per notable release
  helps discovery.

### Release reminder
Publishing is partly manual: pushing the `vX.Y.Z` tag runs the workflow which **uploads** a
deployment to the Central Portal in `VALIDATED` state — you must then click **Publish** on
central.sonatype.com. Don't assume CI publishes on its own.

---

See also: [CONTRIBUTING.md](../CONTRIBUTING.md) (build/test + PR checklist) and
[CLAUDE.md](../CLAUDE.md) (architecture overview).
