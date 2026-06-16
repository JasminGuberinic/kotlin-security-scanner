package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (EL)
 * FindSecBugs: EL_INJECTION
 *
 * dropwizard-validation's self-validating feature evaluates constraint
 * violation templates as EL expressions. Passing user-controlled data
 * to buildConstraintViolationWithTemplate() enables EL injection → RCE.
 *
 * CVE-2020-5245, CVE-2020-11002 (both patched in Dropwizard 1.3.21 / 2.0.3,
 * but pattern can be reintroduced by application code).
 *
 * Compliant:
 *   context.buildConstraintViolationWithTemplate("Value must be positive").addConstraintViolation()
 *
 * Non-compliant:
 *   context.buildConstraintViolationWithTemplate(userValue).addConstraintViolation()
 */
class DropwizardSelfValidatingELRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardSelfValidatingEL",
        severity = Severity.Security,
        description = "buildConstraintViolationWithTemplate() with dynamic message — EL injection enables RCE",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.DW_CONSTRAINT_VIOLATION_TEMPLATE) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (isSafe) return
        reportAt(expression, "buildConstraintViolationWithTemplate() with non-literal — EL injection risk")
    }
}
