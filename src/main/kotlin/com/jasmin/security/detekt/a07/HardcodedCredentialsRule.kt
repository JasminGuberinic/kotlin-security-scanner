package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns.CREDENTIAL_VARIABLE_KEYWORDS
import com.jasmin.security.detekt.core.DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: HARD_CODE_PASSWORD — OWASP A07
class HardcodedCredentialsRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "HardcodedCredentials",
        severity = Severity.Security,
        description = "Hardcoded credential detected — move secrets to environment variables or a vault",
        debt = Debt.TWENTY_MINS
    )

    companion object {
        private const val MIN_CREDENTIAL_LENGTH = 3
    }

    @Suppress("ReturnCount")
    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)
        val name = property.name?.lowercase() ?: return
        if (!looksLikeCredentialVariable(name)) return

        val value = (property.initializer as? KtStringTemplateExpression) ?: return
        if (value.isLiteral() && isSuspiciousValue(value.rawValue())) {
            reportAt(property, "Variable '${property.name}' appears to contain a hardcoded credential")
        }
    }

    private fun looksLikeCredentialVariable(name: String) =
        CREDENTIAL_VARIABLE_KEYWORDS.any { name.contains(it) }

    private fun isSuspiciousValue(value: String) =
        value.length >= MIN_CREDENTIAL_LENGTH && SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(value) }
}
