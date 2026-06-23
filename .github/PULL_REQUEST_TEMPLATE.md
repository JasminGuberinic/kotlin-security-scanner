<!-- Thanks for contributing! Keep the description short and check the boxes. -->

## What & why

<!-- What does this change and why? Link any issue. -->

## Checklist

- [ ] `./gradlew clean build` is green (unit tests pass)
- [ ] If adding/changing a rule: positive, negative, and isolation tests included
- [ ] If adding a rule: registered in the module's `*RuleSetProvider` and `config/detekt/detekt.yml`,
      with a CWE tag (`CweMapping`) and fix hint (`RemediationHints`)
- [ ] If adding a rule: fixture added to `scanner-e2e` and `SafeExamples.kt` stays at zero findings
- [ ] No new false positives; call-receiver checks use `substringAfterLast(".")`, not bare substrings
- [ ] Referenced the relevant OWASP / CWE / FindSecBugs ID
