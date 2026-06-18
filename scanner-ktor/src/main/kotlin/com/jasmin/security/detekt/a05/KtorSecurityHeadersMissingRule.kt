package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// install(DefaultHeaders) without X-Frame-Options and X-Content-Type-Options
// leaves the app exposed to clickjacking and MIME sniffing attacks.
// Compliant:   install(DefaultHeaders) { header("X-Frame-Options", "DENY") }
// Non-compliant: install(DefaultHeaders)  // no security headers configured
class KtorSecurityHeadersMissingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorSecurityHeadersMissing",
        severity = Severity.Security,
        description = "Ktor DefaultHeaders without X-Frame-Options — app is vulnerable to clickjacking",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.KTOR_INSTALL) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg != "DefaultHeaders") return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: ""
        if ("X-Frame-Options" in lambdaText) return
        reportAt(
            expression,
            "install(DefaultHeaders) missing X-Frame-Options — add header(\"X-Frame-Options\", \"DENY\")",
        )
    }
}
