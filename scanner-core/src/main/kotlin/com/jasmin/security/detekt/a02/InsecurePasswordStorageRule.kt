package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.psiUtil.getStrictParentOfType

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: WEAK_MESSAGE_DIGEST_*
 *
 * MD5 and SHA family algorithms lack the work factor and salting needed for
 * password hashing. An attacker with the hash database can crack passwords
 * instantly with rainbow tables or GPU acceleration.
 *
 * Use BCryptPasswordEncoder, Argon2PasswordEncoder, or Pbkdf2PasswordEncoder instead.
 *
 * Compliant:
 *   BCryptPasswordEncoder().encode(password)
 *
 * Non-compliant:
 *   MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
 *   DigestUtils.sha256Hex(password)
 */
class InsecurePasswordStorageRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecurePasswordStorage",
        severity = Severity.Security,
        description = "Weak hash algorithm for password storage — use BCrypt, Argon2, or PBKDF2",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        when {
            callee == DetectionPatterns.MESSAGE_DIGEST_GET_INSTANCE -> checkMessageDigest(expression)
            callee in DetectionPatterns.DIGEST_UTILS_METHODS -> checkDigestUtils(expression)
        }
    }

    @Suppress("ReturnCount")
    private fun checkMessageDigest(expression: KtCallExpression) {
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        if (DetectionPatterns.MESSAGE_DIGEST_CLASS !in parent.receiverExpression.text) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val literal = firstArg as? KtStringTemplateExpression ?: return
        if (literal.hasInterpolation()) return
        val algorithm = literal.text.removeSurrounding("\"").uppercase()
        if (algorithm !in DetectionPatterns.PASSWORD_WEAK_HASH_ALGORITHMS) return
        if (!isInsidePasswordFunction(expression)) return
        reportAt(expression, "MessageDigest.$algorithm is not safe for passwords — use BCrypt or Argon2")
    }

    @Suppress("ReturnCount")
    private fun checkDigestUtils(expression: KtCallExpression) {
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        if (DetectionPatterns.DIGEST_UTILS_CLASS !in parent.receiverExpression.text) return
        if (!isInsidePasswordFunction(expression)) return
        val callee = expression.calleeExpression?.text ?: return
        reportAt(expression, "DigestUtils.$callee() is not safe for passwords — use BCrypt or Argon2")
    }

    @Suppress("ReturnCount")
    private fun isInsidePasswordFunction(expression: KtCallExpression): Boolean {
        val fn = expression.getStrictParentOfType<KtNamedFunction>() ?: return false
        val name = fn.name?.lowercase() ?: return false
        return DetectionPatterns.PASSWORD_FUNCTION_KEYWORDS.any { it in name }
    }
}
