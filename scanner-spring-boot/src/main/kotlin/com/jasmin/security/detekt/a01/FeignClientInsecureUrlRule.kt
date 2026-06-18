package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass

/**
 * OWASP A02 — Cryptographic Failures (cleartext channel)
 *
 * A @FeignClient with a hardcoded http:// URL transmits all requests —
 * including auth headers and request bodies — in cleartext. Any network
 * observer can read credentials and data.
 *
 * Compliant:
 *   @FeignClient(name = "users", url = "https://users-service")
 *   @FeignClient(name = "users")   // service-discovery URL, no hardcoded host
 *
 * Non-compliant:
 *   @FeignClient(name = "users", url = "http://users-service")
 */
class FeignClientInsecureUrlRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "FeignClientInsecureUrl",
        severity = Severity.Security,
        description = "@FeignClient url uses HTTP — credentials and data transmitted in cleartext",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        val annotation = klass.annotationEntries.find {
            it.shortName?.asString() == "FeignClient"
        } ?: return
        val urlArg = annotation.valueArguments.find { arg ->
            arg.getArgumentName()?.asName?.asString() == "url"
        } ?: return
        val urlText = urlArg.getArgumentExpression()?.text ?: return
        if (!urlText.startsWith("\"http://")) return
        reportAt(
            klass,
            "@FeignClient url uses HTTP — switch to HTTPS or remove url and use service discovery",
        )
    }
}
