package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A03 — Injection (Path Traversal)
// PartData.FileItem.originalFileName is attacker-controlled. Passing it directly
// to File() or Path() allows directory traversal: "../../etc/passwd" is valid.
// Compliant:   File(uploadDir, part.originalFileName!!.replace("..", "").substringAfterLast("/"))
// Non-compliant: File(part.originalFileName!!)
class KtorFileUploadTraversalRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorFileUploadTraversal",
        severity = Severity.Security,
        description = "originalFileName used directly in File() — path traversal allows writing outside upload directory",
        debt = Debt.TWENTY_MINS,
    )

    private val fileConstructors = setOf("File", "Path", "Paths")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in fileConstructors) return
        val hasOriginalFileName = expression.valueArguments.any {
            "originalFileName" in (it.getArgumentExpression()?.text ?: "")
        }
        if (!hasOriginalFileName) return
        reportAt(
            expression,
            "$callee() with originalFileName — sanitize with substringAfterLast('/') and reject '..' segments",
        )
    }
}
