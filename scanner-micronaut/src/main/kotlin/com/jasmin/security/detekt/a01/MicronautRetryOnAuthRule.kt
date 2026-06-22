package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A01 — Broken Access Control (Brute Force)
// @Retryable on an authentication or login method retries failed attempts automatically.
// This bypasses any account-lockout or rate-limiting mechanisms and effectively implements
// brute-force login on behalf of the attacker.
// Compliant:   @Retryable(excludes = [AuthenticationException::class]) fun callExternalService()
// Non-compliant: @Retryable fun authenticate(credentials: UsernamePasswordCredentials)
class MicronautRetryOnAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautRetryOnAuth",
        severity = Severity.Security,
        description = "@Retryable on an authentication method retries failed login attempts — bypasses brute-force protection",
        debt = Debt.TWENTY_MINS,
    )

    private val authKeywords = setOf("login", "auth", "authenticate", "signin", "password", "credential", "verify")

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if ("Retryable" !in function.annotationNames()) return
        val name = function.name?.lowercase() ?: return
        if (authKeywords.none { it in name }) return
        reportAt(
            function,
            "@Retryable on authentication method '${function.name}' — exclude AuthenticationException from retries or remove @Retryable",
        )
    }
}
