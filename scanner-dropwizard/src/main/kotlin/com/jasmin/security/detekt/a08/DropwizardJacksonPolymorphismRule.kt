package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A08 — Software and Data Integrity Failures (Jackson Polymorphic Deserialization)
// ObjectMapper.enableDefaultTyping() is a known vector for RCE via deserialization gadgets
// (CVE-2017-7525, CVE-2019-14379 and many related CVEs).
// Compliant:   mapper.activateDefaultTypingAsProperty(validator, OBJECT_AND_NON_CONCRETE, "@class")
// Non-compliant: mapper.enableDefaultTyping()
class DropwizardJacksonPolymorphismRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "DropwizardJacksonPolymorphism",
        severity = Severity.Security,
        description = "ObjectMapper.enableDefaultTyping() enables RCE via deserialization gadgets (CVE-2017-7525)",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "enableDefaultTyping") return
        reportAt(
            expression,
            "enableDefaultTyping() allows attacker-controlled class loading — use activateDefaultTypingAsProperty()",
        )
    }
}
