package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns.INSECURE_RANDOM_CLASSES
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// FindSecBugs: PREDICTABLE_RANDOM — OWASP A07
class InsecureRandomRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureRandom",
        severity = Severity.Security,
        description = "java.util.Random is not cryptographically secure — use SecureRandom for tokens and passwords",
        debt = Debt.TEN_MINS
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee in INSECURE_RANDOM_CLASSES) {
            reportAt(expression, "Replace '$callee' with java.security.SecureRandom in security-sensitive contexts")
        }
    }
}
