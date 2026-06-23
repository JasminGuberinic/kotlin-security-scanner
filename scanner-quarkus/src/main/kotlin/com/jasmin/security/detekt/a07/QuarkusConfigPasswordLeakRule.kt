package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtClass

// OWASP A07 — Identification and Authentication Failures
// @ConfigProperty(name="...", defaultValue="secret") hardcodes a secret as a
// compile-time default. This ends up in class files and container images.
// Compliant:   @ConfigProperty(name="app.secret") lateinit var secret: String
// Non-compliant: @ConfigProperty(name="app.secret", defaultValue="hardcoded-val")
class QuarkusConfigPasswordLeakRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusConfigPasswordLeak",
        severity = Severity.Security,
        description = "@ConfigProperty defaultValue contains a potential secret — remove defaultValue for secrets",
        debt = Debt.TWENTY_MINS,
    )

    private val sensitiveNames = setOf(
        "password", "passwd", "pwd", "secret", "token", "key", "credential", "apikey", "api-key",
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        klass.body?.properties?.forEach { prop ->
            prop.annotationEntries.forEach { checkAnnotation(it) }
        }
        // Quarkus constructor injection: @ConfigProperty on a primary-constructor parameter,
        // e.g. class Svc(@ConfigProperty(name="app.secret", defaultValue="changeme") val s: String)
        klass.primaryConstructor?.valueParameters?.forEach { param ->
            param.annotationEntries.forEach { checkAnnotation(it) }
        }
    }

    @Suppress("ReturnCount")
    private fun checkAnnotation(annotation: KtAnnotationEntry) {
        if (annotation.shortName?.asString() != "ConfigProperty") return
        val args = annotation.valueArguments
        val name = args.find { it.getArgumentName()?.asName?.asString() == "name" }
            ?.getArgumentExpression()?.text?.lowercase() ?: ""
        val isSensitive = sensitiveNames.any { it in name }
        if (!isSensitive) return
        val hasDefault = args.any { it.getArgumentName()?.asName?.asString() == "defaultValue" }
        if (!hasDefault) return
        reportAt(
            annotation,
            "@ConfigProperty with sensitive name has defaultValue — remove defaultValue for credentials",
        )
    }
}
