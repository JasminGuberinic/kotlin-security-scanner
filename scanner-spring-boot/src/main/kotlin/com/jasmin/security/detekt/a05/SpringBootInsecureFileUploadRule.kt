package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtProperty

// OWASP A05 — Security Misconfiguration
// Saving an uploaded file using originalFilename as the target path allows path traversal
// (e.g. "../../etc/cron.d/evil") and may overwrite arbitrary server files.
// Compliant:   val safe = UUID.randomUUID().toString() + ext
// Non-compliant: file.transferTo(File(upload.originalFilename!!))
class SpringBootInsecureFileUploadRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringBootInsecureFileUpload",
        severity = Severity.Security,
        description = "MultipartFile.originalFilename used as file path — path traversal risk",
        debt = Debt.TWENTY_MINS,
    )

    private val pathContextKeywords = setOf("transferTo", "File(", "Paths.get", "resolve")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val hasMultipartParam = function.valueParameters.any {
            "MultipartFile" in (it.typeReference?.text ?: "")
        }
        if (!hasMultipartParam) return
        val bodyText = function.bodyExpression?.text ?: return
        if ("originalFilename" !in bodyText) return
        if (pathContextKeywords.none { it in bodyText }) return
        reportAt(
            function,
            "originalFilename used as file path — sanitize with UUID or validate against allowlist of extensions",
        )
    }

    @Suppress("ReturnCount")
    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)
        val initText = property.initializer?.text ?: return
        if ("originalFilename" !in initText) return
        val propName = property.name?.lowercase() ?: return
        if ("path" !in propName && "file" !in propName && "name" !in propName) return
        reportAt(
            property,
            "originalFilename assigned to variable — validate or replace before using as a file system path",
        )
    }
}
