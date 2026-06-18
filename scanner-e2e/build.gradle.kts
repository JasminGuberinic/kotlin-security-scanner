// End-to-end demo module — intentionally vulnerable Kotlin code.
// Detekt with all scanner rules runs against this code and produces real findings.
//
// Run:    ./gradlew :scanner-e2e:detekt
// Report: scanner-e2e/build/reports/detekt/detekt.html
//
// Expected: 40+ security findings across OWASP Top 10 categories.
// ignoreFailures = true — findings are reported but do not fail the build.
