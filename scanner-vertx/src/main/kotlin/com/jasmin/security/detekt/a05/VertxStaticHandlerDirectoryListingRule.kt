package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression

/**
 * OWASP A05 — Security Misconfiguration (Information Exposure / CWE-548)
 *
 * `StaticHandler.create().setDirectoryListing(true)` makes Vert.x render a browsable index
 * of the served directory, exposing every file name (and often files that were never meant
 * to be public). Keep directory listing off.
 *
 * Non-compliant:
 *   StaticHandler.create("webroot").setDirectoryListing(true)
 */
class VertxStaticHandlerDirectoryListingRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxStaticHandlerDirectoryListing",
        severity = Severity.Security,
        description = "StaticHandler.setDirectoryListing(true) exposes a browsable file index",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text?.substringAfterLast(".") != "setDirectoryListing") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
        if (arg.text != "true") return
        reportAt(expression, "setDirectoryListing(true) exposes a browsable file index — leave it off (default false)")
    }
}
