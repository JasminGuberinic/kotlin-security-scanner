package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtLambdaExpression

/**
 * OWASP A02 — Cryptographic Failures (CWE-297)
 *
 * A HostnameVerifier that always returns true disables SSL hostname validation,
 * allowing MITM attacks even when a valid certificate is present. Complements
 * TrustAllCertsRule which covers the certificate-chain bypass.
 *
 * Compliant:
 *   // Omit setHostnameVerifier entirely — the default verifier is secure
 *
 * Non-compliant:
 *   HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
 *   conn.setHostnameVerifier { _, _ -> true }
 */
class TrustAllHostnamesRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "TrustAllHostnames",
        severity = Severity.Security,
        description = "HostnameVerifier always returns true — SSL hostname verification is disabled",
        debt = Debt.TWENTY_MINS,
    )

    private val setterMethods = setOf("setDefaultHostnameVerifier", "setHostnameVerifier")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee !in setterMethods) return
        val lambda = findLambdaArg(expression) ?: return
        if (isAlwaysTrue(lambda)) {
            reportAt(
                expression,
                "$callee with HostnameVerifier always returning true — remove the setter to restore hostname validation",
            )
        }
    }

    private fun findLambdaArg(expression: KtCallExpression): KtLambdaExpression? {
        expression.lambdaArguments.firstOrNull()?.getLambdaExpression()?.let { return it }
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()
        return firstArg as? KtLambdaExpression
    }

    private fun isAlwaysTrue(lambda: KtLambdaExpression): Boolean {
        val body = lambda.bodyExpression ?: return false
        val stmts = body.statements
        if (stmts.size != 1) return false
        return stmts[0].let { it is KtConstantExpression && it.text == "true" }
    }
}
