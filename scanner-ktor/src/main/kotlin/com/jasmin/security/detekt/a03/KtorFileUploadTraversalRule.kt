package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

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

    private val fileConstructors = setOf("File", "Path")
    private val sanitizers = listOf("substringAfterLast", "replace", "fileName")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        // Match `File(...)`, `Path(...)`, and `Paths.get(...)` (callee `get`, receiver `Paths`).
        val isPathsGet = callee == "get" &&
            (expression.parent as? KtDotQualifiedExpression)
                ?.receiverExpression?.text?.substringAfterLast(".") == "Paths"
        if (callee !in fileConstructors && !isPathsGet) return
        val constructorName = if (isPathsGet) "Paths.get" else callee

        val args = expression.valueArguments.mapNotNull { it.getArgumentExpression()?.text }
        val hasOriginalFileName = args.any { "originalFileName" in it }
        if (!hasOriginalFileName) return
        // Skip when the filename is sanitized inline (substringAfterLast / replace / .fileName).
        val isSanitized = args.any { arg -> sanitizers.any { it in arg } }
        if (isSanitized) return
        reportAt(
            expression,
            "$constructorName() with originalFileName — sanitize with substringAfterLast('/') and reject '..' segments",
        )
    }
}
