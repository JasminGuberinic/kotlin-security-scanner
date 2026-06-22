package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A02 — Cryptographic Failures
// usePlaintext() on a gRPC ManagedChannelBuilder disables TLS entirely.
// All RPC calls — including those carrying JWTs or sensitive payloads — are sent
// as cleartext and can be intercepted on the same network.
// Compliant:   ManagedChannelBuilder.forAddress(host, 443) // TLS by default on port 443
// Non-compliant: ManagedChannelBuilder.forAddress(host, 8080).usePlaintext().build()
class MicronautGrpcInsecureRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "MicronautGrpcInsecure",
        severity = Severity.Security,
        description = "gRPC channel configured with usePlaintext() — all traffic is unencrypted",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee != "usePlaintext") return
        reportAt(
            expression,
            "gRPC channel usePlaintext() disables TLS — remove this call and configure TLS for production channels",
        )
    }
}
