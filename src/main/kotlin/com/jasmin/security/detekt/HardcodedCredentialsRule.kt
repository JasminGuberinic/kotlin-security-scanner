package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

class HardcodedCredentialsRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "HardcodedCredentials",
        severity = Severity.Security,
        description = "Hardcoded credential detected — move to environment variables or a secrets manager",
        debt = Debt.TWENTY_MINS
    )

    companion object {
        private const val MIN_CREDENTIAL_LENGTH = 3
    }

    private val credentialKeywords = setOf(
        "password", "passwd", "pwd", "secret", "apikey", "api_key",
        "token", "auth", "credential", "private_key", "privatekey",
        "access_key", "accesskey", "client_secret", "clientsecret"
    )

    private val safeValuePatterns = listOf(
        Regex("""^\$\{.*}$"""),
        Regex("""^#\{.*}$"""),
        Regex("""^\*+$"""),
        Regex("""^$"""),
        Regex("""^\s+$"""),
        Regex("changeme", RegexOption.IGNORE_CASE),
        Regex("placeholder", RegexOption.IGNORE_CASE),
        Regex("your[-_]?.*here", RegexOption.IGNORE_CASE),
    )

    @Suppress("ReturnCount")
    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)
        val name = property.name?.lowercase() ?: return
        if (credentialKeywords.none { name.contains(it) }) return

        val initializer = property.initializer as? KtStringTemplateExpression ?: return
        val value = initializer.text.removeSurrounding("\"").removeSurrounding("'")

        if (value.length < MIN_CREDENTIAL_LENGTH) return
        if (safeValuePatterns.any { it.containsMatchIn(value) }) return

        report(
            CodeSmell(
                issue,
                Entity.from(property),
                "Variable '${property.name}' appears to contain a hardcoded credential"
            )
        )
    }
}
