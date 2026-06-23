package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType
import org.jetbrains.kotlin.psi.psiUtil.getStrictParentOfType

/**
 * OWASP A05 — Security Misconfiguration (Sensitive Cookie Without 'Secure' / CWE-614)
 *
 * Calling .secure(false) on a Micronaut Cookie sends it over plain HTTP, where it can
 * be captured by a network attacker. Session and auth cookies must be marked secure so
 * the browser only transmits them over HTTPS.
 *
 * Compliant:
 *   Cookie.of("SESSION", id).secure(true).httpOnly(true)
 *
 * Non-compliant:
 *   Cookie.of("SESSION", id).secure(false)              // fluent
 *   val c = Cookie.of("SESSION", id); c.secure(false)   // via local variable
 */
class MicronautInsecureCookieRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautInsecureCookie",
        severity = Severity.Security,
        description = "Cookie marked secure(false) — it will be sent over plain HTTP",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "secure") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
        if (arg.text != "false") return
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        // Fluent form: the chain itself is a Cookie (e.g. Cookie.of(...).secure(false)).
        // Variable form: the receiver is a local val assigned from a Cookie in the same function.
        if (receiver.contains("ookie") || isCookieVariable(expression, receiver.substringAfterLast("."))) {
            reportAt(expression, "Cookie.secure(false) sends the cookie over plain HTTP — call .secure(true)")
        }
    }

    private fun isCookieVariable(expression: KtCallExpression, name: String): Boolean {
        val function = expression.getStrictParentOfType<KtNamedFunction>() ?: return false
        return function.collectDescendantsOfType<KtProperty>().any {
            it.name == name && it.initializer?.text?.contains("ookie") == true
        }
    }
}
