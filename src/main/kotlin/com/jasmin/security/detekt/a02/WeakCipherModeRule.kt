package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns.WEAK_CIPHER_ALGORITHMS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: ECB_MODE, DES_USAGE, TDES_USAGE, NULL_CIPHER — OWASP A02
class WeakCipherModeRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "WeakCipherMode",
        severity = Severity.Security,
        description = "Insecure cipher algorithm or mode — use AES/GCM/NoPadding with a random IV (OWASP A02)",
        debt = Debt.TWENTY_MINS
    )

    @Suppress("ReturnCount")
    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (!expression.isLiteral()) return
        val value = expression.rawValue()
        if (!isWeakCipherSpec(value)) return
        if (!isInsideGetInstanceCall(expression)) return
        reportAt(expression, "Weak cipher '$value' — use \"AES/GCM/NoPadding\" instead")
    }

    private fun isWeakCipherSpec(value: String) = WEAK_CIPHER_ALGORITHMS.any { it.containsMatchIn(value) }

    // String → KtValueArgument → KtValueArgumentList → KtCallExpression
    private fun isInsideGetInstanceCall(expression: KtStringTemplateExpression) =
        expression.ancestor(levels = 3)?.text?.startsWith("getInstance") == true
}
