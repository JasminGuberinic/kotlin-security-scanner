package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 * Comparing credentials.password == "literal" is both insecure (timing attack) and
 * means the plaintext password is hardcoded — use BCrypt.matches() instead.
 */
class KtorHardcodedPasswordComparisonRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorHardcodedPasswordComparison",
        severity = Severity.Security,
        description = "Hardcoded password comparison — hash passwords and use constant-time comparison",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        if (expression.operationToken != KtTokens.EQEQ) return
        val left = expression.left ?: return
        val right = expression.right ?: return
        val combinedText = left.text + right.text
        if (".password" !in combinedText && ".passwd" !in combinedText) return
        val rightLiteral = right is KtStringTemplateExpression && !right.hasInterpolation()
        val leftLiteral = left is KtStringTemplateExpression && !left.hasInterpolation()
        if (!rightLiteral && !leftLiteral) return
        reportAt(
            expression,
            "Password compared against a literal string — hash passwords with BCrypt and use secure comparison",
        )
    }
}
