package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression

/**
 * OWASP A05 — Security Misconfiguration (Uncontrolled Resource Consumption / CWE-400)
 *
 * `BodyHandler.create()` without `setBodyLimit(...)` accepts request bodies of unbounded
 * size, so a single large upload can exhaust memory (DoS). Set an explicit body limit.
 *
 * Compliant:
 *   BodyHandler.create().setBodyLimit(10 * 1024 * 1024)
 *
 * Non-compliant:
 *   router.route().handler(BodyHandler.create())
 */
class VertxBodyHandlerNoLimitRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxBodyHandlerNoLimit",
        severity = Severity.Security,
        description = "BodyHandler.create() without setBodyLimit — unbounded request body (DoS)",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "create") return
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        if (receiver.substringAfterLast(".") != "BodyHandler") return
        // Safe if the surrounding call chain sets a body limit (e.g. BodyHandler.create().setBodyLimit(n)).
        if (outermostChain(expression).text.contains("setBodyLimit")) return
        reportAt(
            expression,
            "BodyHandler.create() without setBodyLimit — set an explicit limit, e.g. .setBodyLimit(10 * 1024 * 1024)",
        )
    }

    private fun outermostChain(expression: KtCallExpression): KtExpression {
        var node: KtExpression = expression
        while (node.parent is KtDotQualifiedExpression) node = node.parent as KtDotQualifiedExpression
        return node
    }
}
