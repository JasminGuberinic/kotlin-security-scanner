package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: HARD_CODE_KEY
 *
 * A hardcoded JWT signing secret allows offline dictionary attacks against
 * captured tokens. Anyone with the source code can forge valid JWTs.
 *
 * Covers:
 *   - Auth0 JWT:       Algorithm.HMAC256("secret")
 *   - JJWT v0:         Jwts.builder().signWith(alg, "secret")
 *   - Nimbus JOSE JWT: MACSigner("secret") / MACVerifier("secret")
 *   - JJWT v1:         Keys.hmacShaKeyFor("secret".toByteArray())
 *
 * Compliant:
 *   Algorithm.HMAC256(System.getenv("JWT_SECRET"))
 *   MACSigner(System.getenv("JWT_SECRET").toByteArray())
 *
 * Non-compliant:
 *   Algorithm.HMAC256("my-secret-key")
 *   MACSigner("hardcoded-secret")
 *   Keys.hmacShaKeyFor("hardcoded".toByteArray())
 */
class JwtWeakSecretRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "JwtWeakSecret",
        severity = Severity.Security,
        description = "JWT signed with a hardcoded secret — use an environment variable or key store",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val simpleName = callee.substringAfterLast(".")
        if (simpleName !in DetectionPatterns.JWT_HMAC_METHODS && simpleName != DetectionPatterns.JWT_SIGN_WITH_METHOD) return
        val hasLiteralSecret = expression.valueArguments.any { isHardcodedArg(it.getArgumentExpression()) }
        if (!hasLiteralSecret) return
        reportAt(
            expression,
            "$simpleName() with hardcoded secret — load the signing key from an environment variable or key store",
        )
    }

    private fun isHardcodedArg(expr: KtExpression?): Boolean {
        if (expr == null) return false
        if (expr is KtStringTemplateExpression) return !expr.hasInterpolation()
        // handles "literal".toByteArray() / .encodeToByteArray()
        if (expr is KtDotQualifiedExpression) {
            val recv = expr.receiverExpression
            return recv is KtStringTemplateExpression && !recv.hasInterpolation()
        }
        return false
    }
}
