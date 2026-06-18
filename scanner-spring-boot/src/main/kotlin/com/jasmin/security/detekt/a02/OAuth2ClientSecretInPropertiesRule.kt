package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import java.util.Properties

class OAuth2ClientSecretInPropertiesRule(config: Config) : PropertiesSecurityRule(config) {

    override val issue = Issue(
        id = "OAuth2ClientSecretInProperties",
        severity = Severity.Security,
        description = "OAuth2 client-secret hardcoded in properties — use environment variable or Vault",
        debt = Debt.TWENTY_MINS,
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> =
        props.entries
            .filter { (k, _) ->
                k.toString().contains("oauth2") &&
                    (k.toString().endsWith("client-secret") || k.toString().endsWith("client_secret"))
            }
            .filterNot { (_, v) ->
                DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.any { it.containsMatchIn(v.toString()) }
            }
            .map { (k, _) ->
                k.toString() to "OAuth2 client-secret hardcoded — use \${OAUTH2_CLIENT_SECRET}"
            }
}
