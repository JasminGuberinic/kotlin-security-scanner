package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A02 — Cryptographic Failures
// @Client("http://service") sends all requests — including authentication tokens — in plaintext.
// Compliant:   @Client("https://service") or @Client("\${service.url}") with url set to https in config
// Non-compliant: @Client("http://internal-service")
class MicronautInsecureHttpClientRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautInsecureHttpClient",
        severity = Severity.Security,
        description = "@Client URL uses plain HTTP — all data including auth tokens sent in cleartext",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitAnnotationEntry(annotationEntry: KtAnnotationEntry) {
        super.visitAnnotationEntry(annotationEntry)
        if (annotationEntry.shortName?.asString() != "Client") return
        val valueExpr = annotationEntry.valueArguments.firstOrNull()
            ?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        val raw = valueExpr.rawValue()
        if (!raw.contains("http://")) return
        reportAt(
            annotationEntry,
            "@Client(\"$raw\") uses plain HTTP — change to https:// to encrypt data in transit",
        )
    }
}
