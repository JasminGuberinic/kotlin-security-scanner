package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A08 — Software and Data Integrity Failures
// Accepting "application/x-java-serialized-object" enables Java deserialization
// attacks. Any gadget chain on the classpath can achieve remote code execution.
// CVE-2015-4852 (WebLogic), CVE-2016-4437 (Apache Shiro) — both via Java deserialization.
// Compliant:   use JSON or other text-based content types
// Non-compliant: ContentType.parse("application/x-java-serialized-object")
class KtorInsecureContentNegotiationRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KtorInsecureContentNegotiation",
        severity = Severity.Security,
        description = "application/x-java-serialized-object enables RCE via Java deserialization gadget chains",
        debt = Debt.TWENTY_MINS,
    )

    private val dangerousContentTypes = listOf(
        "x-java-serialized-object",
        "application/java-serialized-object",
    )

    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        val text = expression.text
        if (dangerousContentTypes.any { it in text }) {
            reportAt(
                expression,
                "Java serialization content type enables RCE — use application/json instead",
            )
        }
    }
}
