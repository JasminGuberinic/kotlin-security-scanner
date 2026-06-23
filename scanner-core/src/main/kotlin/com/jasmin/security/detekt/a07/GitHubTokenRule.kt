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
 * GitHub personal access / OAuth / app tokens (ghp_, gho_, ghu_, ghs_, ghr_, and
 * fine-grained github_pat_) grant repository and org access. A hardcoded token
 * must be revoked under Developer settings the moment it is committed.
 *
 * Non-compliant:
 *   val token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
 */
class GitHubTokenRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "GitHubToken",
        severity = Severity.Security,
        description = "Hardcoded GitHub token — revoke it and load from environment or a secret manager",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (DetectionPatterns.GITHUB_TOKEN_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "Hardcoded GitHub token detected — revoke it and load from environment or a secret manager",
            )
        }
    }
}
