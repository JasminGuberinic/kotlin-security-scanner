package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// FindSecBugs: SPRING_CSRF_PROTECTION_DISABLED — OWASP A05
class SpringCsrfDisabledRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "SpringCsrfDisabled",
        severity = Severity.Security,
        description = "CSRF protection is disabled — remove .csrf { disable() } or .csrf().disable() " +
            "and handle CSRF with tokens in your frontend (OWASP A05)",
        debt = Debt.TWENTY_MINS
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)

        val calleeName = expression.calleeExpression?.text ?: return

        // Pattern 1: csrf { disable() } — Spring Security Kotlin DSL
        if (calleeName == "csrf") {
            val lambda = expression.lambdaArguments.firstOrNull()
            if (lambda != null && lambda.text.contains("disable")) {
                report(CodeSmell(issue, Entity.from(expression), issue.description))
                return
            }
        }

        // Pattern 2: .disable() called on csrf() — legacy fluent API
        if (calleeName == "disable") {
            val parent = expression.parent
            if (parent is KtDotQualifiedExpression) {
                val receiver = parent.receiverExpression
                if (receiver.text.contains("csrf")) {
                    report(CodeSmell(issue, Entity.from(expression), issue.description))
                    return
                }
            }
        }

        // Pattern 3: csrf(CsrfConfigurer::disable) — method reference style
        if (calleeName == "csrf") {
            val args = expression.valueArguments
            if (args.any { it.text.contains("disable") }) {
                report(CodeSmell(issue, Entity.from(expression), issue.description))
            }
        }
    }
}
