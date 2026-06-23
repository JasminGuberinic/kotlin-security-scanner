package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A05 — Security Misconfiguration (Incorrect Permission Assignment / CWE-732)
 *
 * Granting world (others) read/write/execute on a file exposes its contents — often
 * secrets, keys, or uploads — to every local account. Flags
 * PosixFilePermissions.fromString("...") whose "others" group is permissive and
 * File.setWritable/Readable/Executable(true, false) (ownerOnly = false → world-wide).
 *
 * Compliant:
 *   PosixFilePermissions.fromString("rw-------")
 *   file.setReadable(true, true) // owner only
 *
 * Non-compliant:
 *   PosixFilePermissions.fromString("rwxrwxrwx")
 *   file.setWritable(true, false)
 */
class InsecureFilePermissionsRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureFilePermissions",
        severity = Severity.Security,
        description = "File granted world-accessible permissions — restrict access to the owner",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        when (callee) {
            DetectionPatterns.POSIX_FROM_STRING -> checkPosixString(expression)
            in DetectionPatterns.WORLD_ACCESS_SETTERS -> checkWorldSetter(expression)
        }
    }

    private fun checkPosixString(expression: KtCallExpression) {
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (arg !is KtStringTemplateExpression || arg.hasInterpolation()) return
        val perms = arg.rawValue()
        // rwxrwxrwx — chars 6..8 are the "others" group; any non-dash means world access.
        if (perms.length == 9 && perms.substring(6).any { it != '-' }) {
            reportAt(
                expression,
                "PosixFilePermissions.fromString(\"$perms\") grants access to all users — restrict the others group to ---",
            )
        }
    }

    private fun checkWorldSetter(expression: KtCallExpression) {
        val args = expression.valueArguments
        if (args.size != 2) return
        val enabling = (args[0].getArgumentExpression() as? KtConstantExpression)?.text == "true"
        val ownerOnly = (args[1].getArgumentExpression() as? KtConstantExpression)?.text
        if (enabling && ownerOnly == "false") {
            val callee = expression.calleeExpression?.text?.substringAfterLast(".")
            reportAt(
                expression,
                "$callee(true, false) applies the permission to every user — pass ownerOnly = true",
            )
        }
    }
}
