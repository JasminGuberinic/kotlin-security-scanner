package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 *
 * A signed JWT literal (three base64url segments, header beginning "eyJ") embedded
 * in source is a bearer credential: anyone with the source can replay it until it
 * expires. Tokens belong in secure storage or short-lived runtime issuance, never
 * in code or test fixtures committed to the repository.
 *
 * Non-compliant:
 *   val token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignature123"
 */
class HardcodedJwtTokenRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedJwtToken",
        severity = Severity.Security,
        description = "Hardcoded JWT bearer token — issue tokens at runtime, never commit them",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (DetectionPatterns.JWT_LITERAL_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "Hardcoded JWT bearer token detected — issue tokens at runtime and never commit them",
            )
        }
    }
}
