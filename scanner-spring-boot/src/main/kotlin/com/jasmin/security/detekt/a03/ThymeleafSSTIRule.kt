package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (Server-Side Template Injection)
 * CVE-2023-38286 (Spring + Thymeleaf SSTI)
 *
 * Passing user-controlled data as the template name or template string to
 * TemplateEngine.process() allows attackers to inject Thymeleaf expressions
 * that execute arbitrary Java code on the server.
 *
 * Compliant:
 *   templateEngine.process("user-profile", ctx)
 *
 * Non-compliant:
 *   templateEngine.process(templateName, ctx)       // non-literal template name
 *   templateEngine.process("Hello, ${name}", ctx)   // interpolated first arg
 */
class ThymeleafSSTIRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ThymeleafSSTI",
        severity = Severity.Security,
        description = "TemplateEngine.process() with non-literal template — Thymeleaf SSTI risk",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.THYMELEAF_PROCESS_METHOD) return
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        val receiverLower = parent.receiverExpression.text.lowercase()
        if (
            DetectionPatterns.THYMELEAF_ENGINE_RECEIVERS.none { it in receiverLower }
        ) {
            return
        }
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (isSafe) return
        reportAt(expression, "TemplateEngine.process() with dynamic template — use a static template name")
    }
}
