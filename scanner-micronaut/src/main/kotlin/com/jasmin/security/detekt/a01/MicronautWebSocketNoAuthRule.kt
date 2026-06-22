package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass

// OWASP A01 — Broken Access Control
// @ServerWebSocket endpoints are not covered by Micronaut's standard HTTP security filter chain.
// Without @Secured the handshake completes unauthenticated for any caller.
// Compliant:   @ServerWebSocket("/chat") @Secured(SecurityRule.IS_AUTHENTICATED) class ChatHandler
// Non-compliant: @ServerWebSocket("/chat") class ChatHandler  // no @Secured
class MicronautWebSocketNoAuthRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautWebSocketNoAuth",
        severity = Severity.Security,
        description = "@ServerWebSocket endpoint has no @Secured — WebSocket connections bypass HTTP security filters",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        val annotations = klass.annotationNames()
        if ("ServerWebSocket" !in annotations) return
        if ("Secured" in annotations) return
        reportAt(
            klass,
            "@ServerWebSocket endpoint '${klass.name}' has no @Secured — add @Secured(SecurityRule.IS_AUTHENTICATED) to restrict access",
        )
    }
}
