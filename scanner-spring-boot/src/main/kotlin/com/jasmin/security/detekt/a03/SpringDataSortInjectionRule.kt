package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (Sort parameter injection)
 * CVE-2016-6652 — Spring Data JPA Sort injection
 *
 * Sort.by(userControlledField) passes the field name directly into JPQL ORDER BY,
 * allowing injection of arbitrary SQL/JPQL via the sort parameter.
 *
 * Compliant:
 *   val allowed = setOf("name", "email")
 *   require(field in allowed)
 *   Sort.by(field)
 *
 * Non-compliant:
 *   Sort.by(request.getParameter("sort"))
 */
class SpringDataSortInjectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringDataSortInjection",
        severity = Severity.Security,
        description = "Sort.by() with non-literal argument — user-controlled sort field enables JPQL injection",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        // Sort.by(x) is DotQualifiedExpression: receiver=Sort, selector=by(x)
        // so calleeExpression.text is "by", not "Sort.by"
        if (expression.calleeExpression?.text != "by") return
        val dotExpr = expression.parent as? KtDotQualifiedExpression ?: return
        if (dotExpr.receiverExpression.text != "Sort") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        if ("Sort.Direction" in (firstArg.text)) return
        reportAt(
            dotExpr,
            "Sort.by() with dynamic field name — validate against an allowlist of known field names",
        )
    }
}
