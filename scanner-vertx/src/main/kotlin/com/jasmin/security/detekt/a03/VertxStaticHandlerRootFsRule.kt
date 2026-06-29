package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (Path Traversal / CWE-22)
 *
 * Allowing a Vert.x StaticHandler to serve the filesystem root —
 * `StaticHandler.create("/")` or `setAllowRootFileSystemAccess(true)` — lets a crafted
 * request read arbitrary files on the host. Serve a dedicated webroot only.
 *
 * Non-compliant:
 *   StaticHandler.create("/")
 *   StaticHandler.create().setAllowRootFileSystemAccess(true)
 */
class VertxStaticHandlerRootFsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxStaticHandlerRootFs",
        severity = Severity.Security,
        description = "StaticHandler serves the filesystem root — arbitrary file disclosure",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        when (callee) {
            "setAllowRootFileSystemAccess" -> {
                val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
                if (arg.text == "true") {
                    reportAt(expression, "setAllowRootFileSystemAccess(true) exposes the whole filesystem — serve a dedicated webroot")
                }
            }
            "create" -> {
                val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
                if (receiver.substringAfterLast(".") != "StaticHandler") return
                val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtStringTemplateExpression ?: return
                if (!arg.hasInterpolation() && arg.rawValue() == "/") {
                    reportAt(expression, "StaticHandler.create(\"/\") serves the filesystem root — use a dedicated webroot directory")
                }
            }
        }
    }
}
