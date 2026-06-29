package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (Missing Authorization / CWE-862)
 *
 * A Vert.x SockJS event-bus bridge with a permitted entry matching everything
 * (`PermittedOptions().setAddressRegex(".*")` or `setAddress("*")`) exposes the entire
 * event bus to browser clients — any address can be published to / consumed. Permit only
 * the specific addresses the frontend needs.
 *
 * Non-compliant:
 *   SockJSBridgeOptions().addInboundPermitted(PermittedOptions().setAddressRegex(".*"))
 */
class VertxEventBusBridgeOpenRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "VertxEventBusBridgeOpen",
        severity = Severity.Security,
        description = "Event-bus bridge permits all addresses (\".*\"/\"*\") — exposes the whole bus to clients",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "setAddressRegex" && callee != "setAddress") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        if (arg.hasInterpolation()) return
        val value = arg.rawValue()
        val wildcard = (callee == "setAddressRegex" && (value == ".*" || value == ".+")) ||
            (callee == "setAddress" && value == "*")
        if (wildcard) {
            reportAt(
                expression,
                "$callee(\"$value\") permits every event-bus address — restrict the bridge to the exact addresses the client needs",
            )
        }
    }
}
