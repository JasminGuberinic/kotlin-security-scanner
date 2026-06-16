package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: ECB_MODE, DES_USAGE, TDES_USAGE, NULL_CIPHER — OWASP A02
class WeakCipherModeRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "WeakCipherMode",
        severity = Severity.Security,
        description = "Insecure cipher algorithm or mode detected — use AES/GCM/NoPadding with a random IV (OWASP A02)",
        debt = Debt.TWENTY_MINS
    )

    private val weakPatterns = listOf(
        Regex("""/ECB/""", RegexOption.IGNORE_CASE),
        Regex("""^DES[^e]""", RegexOption.IGNORE_CASE),
        Regex("""^DESede""", RegexOption.IGNORE_CASE),
        Regex("""^RC2""", RegexOption.IGNORE_CASE),
        Regex("""^RC4""", RegexOption.IGNORE_CASE),
        Regex("""^Blowfish""", RegexOption.IGNORE_CASE),
        Regex("""NullCipher""", RegexOption.IGNORE_CASE),
    )

    @Suppress("ReturnCount")
    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return

        val value = expression.text.removeSurrounding("\"")
        if (weakPatterns.none { it.containsMatchIn(value) }) return

        // Walk up: KtStringTemplateExpression → KtValueArgument → KtValueArgumentList → KtCallExpression
        val callText = expression.parent?.parent?.parent?.text ?: return
        if (!callText.startsWith("getInstance")) return

        report(
            CodeSmell(
                issue,
                Entity.from(expression),
                "Weak cipher specification '$value' — use \"AES/GCM/NoPadding\" instead"
            )
        )
    }
}
