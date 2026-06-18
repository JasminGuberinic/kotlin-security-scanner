package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass

// OWASP A02 — Cryptographic Failures
// @RegisterRestClient(baseUri="http://...") sends request bodies and auth tokens
// over plaintext. Switch to https:// or configure the URI via properties.
// Compliant:   @RegisterRestClient(configKey="my-svc")  // URI in application.properties
// Non-compliant: @RegisterRestClient(baseUri="http://payment-service:8080")
class QuarkusRestClientInsecureUrlRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusRestClientInsecureUrl",
        severity = Severity.Security,
        description = "@RegisterRestClient baseUri uses HTTP — request bodies transmitted in cleartext",
        debt = Debt.TEN_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        val annotation = klass.annotationEntries
            .find { it.shortName?.asString() == "RegisterRestClient" } ?: return
        val baseUriArg = annotation.valueArguments.find { arg ->
            arg.getArgumentName()?.asName?.asString() == "baseUri"
        } ?: return
        val value = baseUriArg.getArgumentExpression()?.text ?: return
        if (!value.startsWith("\"http://")) return
        reportAt(klass, "@RegisterRestClient baseUri uses HTTP — switch to https:// or use configKey")
    }
}
