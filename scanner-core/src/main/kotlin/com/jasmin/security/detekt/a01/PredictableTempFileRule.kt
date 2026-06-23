package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (Insecure Temporary File / CWE-377)
 *
 * Constructing a File at a fixed, world-writable temp path (/tmp, /var/tmp, /dev/shm)
 * is predictable: a local attacker can pre-create the path as a symlink or read its
 * contents (race / information disclosure). Use Files.createTempFile, which generates
 * an unpredictable name with owner-only permissions.
 *
 * Compliant:
 *   val tmp = Files.createTempFile("upload", ".tmp")
 *
 * Non-compliant:
 *   File("/tmp/session-data.txt")
 */
class PredictableTempFileRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "PredictableTempFile",
        severity = Severity.Security,
        description = "File at a fixed temp path — use Files.createTempFile for an unpredictable, owner-only file",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "File") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression || firstArg.hasInterpolation()) return
        val path = firstArg.rawValue()
        if (DetectionPatterns.INSECURE_TEMP_PATH_PREFIXES.any { path.startsWith(it) }) {
            reportAt(
                expression,
                "File(\"$path\") uses a predictable temp location — use Files.createTempFile for an unpredictable, owner-only file",
            )
        }
    }
}
