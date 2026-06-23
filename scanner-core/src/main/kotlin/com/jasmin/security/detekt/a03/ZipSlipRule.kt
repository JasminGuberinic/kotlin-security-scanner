package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A03 — Injection (Path Traversal during archive extraction)
 *
 * A ZipEntry name is attacker-controlled and may contain "../" sequences. Resolving
 * it directly into an output path — File(dir, entry.name), dir.resolve(entry.name),
 * Paths.get(dir, entry.name) — lets a crafted archive write outside the target
 * directory (Zip Slip, e.g. CVE-2018-1002200). Normalize and verify containment.
 *
 * Compliant:
 *   val target = dir.resolve(entry.name).normalize()
 *   require(target.startsWith(dir)) { "Zip Slip detected" }
 *
 * Non-compliant:
 *   File(outputDir, zipEntry.name)
 *   outputDir.resolve(entry.name)
 */
class ZipSlipRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ZipSlip",
        severity = Severity.Security,
        description = "ZipEntry name resolved into an output path — normalize and verify it stays inside the target dir",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee !in DetectionPatterns.PATH_SINK_METHODS) return
        val usesEntryName = expression.valueArguments.any { arg ->
            val argExpr = arg.getArgumentExpression() as? KtDotQualifiedExpression ?: return@any false
            val selector = argExpr.selectorExpression?.text ?: return@any false
            // ZipEntry.getName() -> entry.name in Kotlin; receiver names a zip entry.
            selector == "name" && isZipEntryReceiver(argExpr.receiverExpression.text)
        }
        if (usesEntryName) {
            reportAt(
                expression,
                "ZipEntry name resolved into a path — call normalize() and require(it.startsWith(targetDir)) to block Zip Slip",
            )
        }
    }

    private fun isZipEntryReceiver(receiver: String): Boolean {
        val lower = receiver.lowercase()
        return "entry" in lower || "zip" in lower
    }
}
