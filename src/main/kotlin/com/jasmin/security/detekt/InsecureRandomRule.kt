package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

class InsecureRandomRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "InsecureRandom",
        severity = Severity.Security,
        description = "java.util.Random is not cryptographically secure — use SecureRandom for tokens and passwords",
        debt = Debt.TEN_MINS
    )

    private val insecureRandomClasses = setOf("Random", "ThreadLocalRandom")

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val calleeText = expression.calleeExpression?.text ?: return
        if (calleeText !in insecureRandomClasses) return
        report(
            CodeSmell(
                issue,
                Entity.from(expression),
                "Use of '$calleeText' detected — replace with SecureRandom for security-sensitive contexts"
            )
        )
    }
}
