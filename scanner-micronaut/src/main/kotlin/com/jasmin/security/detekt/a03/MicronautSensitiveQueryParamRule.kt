package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtParameter

// OWASP A03 — Injection (CWE-598: Sensitive Data in URL Query Strings)
// @QueryValue("password") exposes credentials in the URL, which is logged by
// proxies, browsers, and server access logs. Use request body or Authorization header.
// Compliant:   @Body credentials: LoginRequest  (password inside body)
// Non-compliant: @Get("/login") fun login(@QueryValue password: String)
class MicronautSensitiveQueryParamRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautSensitiveQueryParam",
        severity = Severity.Security,
        description = "Sensitive data passed as @QueryValue — URL parameters are logged by proxies and servers",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitParameter(parameter: KtParameter) {
        super.visitParameter(parameter)
        val annotations = parameter.annotationNames()
        if ("QueryValue" !in annotations) return

        val paramName = parameter.name?.lowercase() ?: ""
        val annotationValue = parameter.annotationEntries
            .find { it.shortName?.asString() == "QueryValue" }
            ?.valueArguments?.firstOrNull()?.getArgumentExpression()?.text
            ?.removeSurrounding("\"")?.lowercase() ?: ""

        val checkIn = "$paramName $annotationValue"
        if (DetectionPatterns.SENSITIVE_LOG_KEYWORDS.none { it in checkIn }) return

        reportAt(
            parameter,
            "@QueryValue \"$paramName\" — sensitive data in URL is logged by proxies; use @Body or Authorization header",
        )
    }
}
