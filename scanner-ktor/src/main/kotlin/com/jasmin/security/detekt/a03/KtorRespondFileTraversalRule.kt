package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A03 — Injection (Path Traversal / CWE-22)
 *
 * call.respondFile(baseDir, request.parameters["path"]) serves a file whose path comes
 * from the request. A "../../etc/passwd" value escapes baseDir and discloses arbitrary
 * files. Resolve and verify the path stays inside baseDir, or use the static-content
 * plugin which does this for you.
 *
 * Non-compliant:
 *   call.respondFile(baseDir, call.parameters["file"]!!)
 */
class KtorRespondFileTraversalRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorRespondFileTraversal",
        severity = Severity.Security,
        description = "respondFile path taken from request parameters — verify it stays inside the base directory",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "respondFile") return
        val fromRequest = expression.valueArguments.any { it.text.contains("parameters") }
        if (fromRequest) {
            reportAt(
                expression,
                "respondFile path comes from request parameters — resolve().normalize() and require it stays under baseDir",
            )
        }
    }
}
