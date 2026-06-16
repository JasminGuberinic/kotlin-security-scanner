package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: HARD_CODE_KEY
 *
 * A hardcoded JWT signing secret allows offline dictionary attacks against
 * captured tokens. Anyone with the source code can forge valid JWTs.
 *
 * Compliant:
 *   Algorithm.HMAC256(System.getenv("JWT_SECRET"))
 *
 * Non-compliant:
 *   Algorithm.HMAC256("my-secret-key")
 *   Jwts.builder().signWith(SignatureAlgorithm.HS256, "hardcoded")
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
        if (
            callee !in DetectionPatterns.JWT_HMAC_METHODS &&
            callee != DetectionPatterns.JWT_SIGN_WITH_METHOD
        ) {
            return
        }
        val hasLiteralSecret = expression.valueArguments.any {
            val e = it.getArgumentExpression()
            e is KtStringTemplateExpression && !e.hasInterpolation()
        }
        if (!hasLiteralSecret) return
        reportAt(
            expression,
            "$callee() with hardcoded secret — load the signing key from an environment variable or key store",
        )
    }
}
