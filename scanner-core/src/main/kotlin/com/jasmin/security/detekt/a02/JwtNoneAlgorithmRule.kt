package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: JWT_NONE_ALGORITHM
 *
 * JWT signed with the "none" algorithm carries no cryptographic signature.
 * Any attacker can forge arbitrary tokens by stripping the signature field.
 *
 * Compliant:
 *   Jwts.builder().signWith(SignatureAlgorithm.HS256, secret).compact()
 *
 * Non-compliant:
 *   Jwts.builder().signWith(SignatureAlgorithm.NONE, "").compact()
 *   JWT.require(Algorithm.none()).build()
 */
class JwtNoneAlgorithmRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "JwtNoneAlgorithm",
        severity = Severity.Security,
        description = "JWT signed with 'none' algorithm — token signature is not verified, can be forged",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        when (callee) {
            DetectionPatterns.JWT_SIGN_WITH_METHOD -> {
                val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
                if (DetectionPatterns.JWT_NONE_ALGORITHM_TEXT !in firstArg.text) return
                reportAt(expression, "signWith(NONE) removes JWT signature verification — use HS256 or RS256")
            }
            DetectionPatterns.JWT_NONE_METHOD -> {
                val parentDot = expression.parent as? KtDotQualifiedExpression ?: return
                if (!parentDot.receiverExpression.text.endsWith(DetectionPatterns.AUTH0_ALGORITHM_CLASS)) return
                reportAt(expression, "Algorithm.none() disables JWT verification — use HMAC256 or RSA256")
            }
        }
    }
}
