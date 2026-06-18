package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

// OWASP A02 — Cryptographic Failures (JWT audience not validated)
// Without quarkus.oidc.token.audience, Quarkus accepts JWTs issued for any audience.
// An attacker can reuse a token from a different service in the same IdP realm.
// Compliant:   quarkus.oidc.token.audience=my-service
// Non-compliant: quarkus.oidc.auth-server-url set, but token.audience missing
@Suppress("ReturnCount")
class QuarkusOidcAudienceMissingRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusOidcAudienceMissing",
        severity = Severity.Security,
        description = "Quarkus OIDC configured without token.audience — JWT audience not validated",
        debt = Debt.TWENTY_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val hasOidc = props.keys.any { it.toString().startsWith("quarkus.oidc.auth-server-url") }
        if (!hasOidc) return emptyList()
        val hasAudience = props.keys.any { it.toString().contains("quarkus.oidc.token.audience") }
        if (hasAudience) return emptyList()
        return listOf(
            "quarkus.oidc.token.audience" to
                "OIDC enabled but token.audience not set — set quarkus.oidc.token.audience=<your-service-name>",
        )
    }
}
