package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 *
 * SecretKeySpec wrapping a hardcoded byte array or string embeds the encryption key
 * in source code and any build artifact. Anyone with the source can decrypt all data.
 *
 * Compliant:
 *   val keyBytes = Base64.getDecoder().decode(System.getenv("AES_KEY"))
 *   SecretKeySpec(keyBytes, "AES")
 *
 * Non-compliant:
 *   SecretKeySpec(byteArrayOf(0x01, 0x02, ...), "AES")
 *   SecretKeySpec("my-secret-key!!".toByteArray(), "AES")
 */
class HardcodedAesKeyRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedAesKey",
        severity = Severity.Security,
        description = "Symmetric encryption key is a hardcoded literal — load from a KeyStore or environment variable",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "SecretKeySpec") return
        val args = expression.valueArguments
        if (args.isEmpty()) return
        val keyArg = args[0].getArgumentExpression() ?: return
        if (!isHardcodedKeyArg(keyArg)) return
        reportAt(
            expression,
            "SecretKeySpec with hardcoded key material — load from a KeyStore or environment variable",
        )
    }

    private fun isHardcodedKeyArg(expr: KtExpression): Boolean {
        // "literal".toByteArray() or "literal".encodeToByteArray()
        if (expr is KtDotQualifiedExpression) {
            val recv = expr.receiverExpression
            return recv is KtStringTemplateExpression && !recv.hasInterpolation()
        }
        // byteArrayOf(0x01, 0x02, ...) — all numeric constants
        if (expr is KtCallExpression) {
            val innerCallee = expr.calleeExpression?.text ?: return false
            if (innerCallee != "byteArrayOf") return false
            return expr.valueArguments.all { it.getArgumentExpression() is KtConstantExpression }
        }
        return false
    }
}
