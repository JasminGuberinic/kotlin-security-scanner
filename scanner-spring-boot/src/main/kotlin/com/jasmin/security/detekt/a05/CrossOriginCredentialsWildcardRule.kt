package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A05 — Security Misconfiguration (CORS with credentials)
 *
 * @CrossOrigin(origins = ["*"], allowCredentials = "true") is rejected by browsers,
 * but combined with a permissive backend may enable CSRF or session-riding attacks
 * when origins is set to a broad pattern. Credentials should only be allowed for
 * explicitly trusted, specific origins.
 *
 * Compliant:
 *   @CrossOrigin(origins = ["https://app.example.com"], allowCredentials = "true")
 *
 * Non-compliant:
 *   @CrossOrigin(origins = ["*"], allowCredentials = "true")
 *   @CrossOrigin(allowCredentials = "true")   // defaults to reflecting Origin header
 */
class CrossOriginCredentialsWildcardRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "CrossOriginCredentialsWildcard",
        severity = Severity.Security,
        description = "@CrossOrigin with allowCredentials — verify origins are restricted to trusted domains",
        debt = Debt.TEN_MINS,
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        klass.annotationEntries.forEach { checkAnnotation(it) }
    }

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        function.annotationEntries.forEach { checkAnnotation(it) }
    }

    @Suppress("ReturnCount")
    private fun checkAnnotation(annotation: KtAnnotationEntry) {
        if (annotation.shortName?.asString() != "CrossOrigin") return
        val text = annotation.text
        val hasCredentials = "allowCredentials" in text && "\"true\"" in text
        if (!hasCredentials) return
        // Only inspect the `origins` argument for a wildcard — `methods=["*"]` etc. must not trip this.
        val originsArg = annotation.valueArguments.firstOrNull {
            it.getArgumentName()?.asName?.asString() == "origins"
        }
        val hasWildcard = if (originsArg == null) {
            // No explicit origins → Spring reflects the Origin header, which is itself unsafe with credentials.
            true
        } else {
            "\"*\"" in (originsArg.getArgumentExpression()?.text ?: "")
        }
        if (!hasWildcard) return
        reportAt(
            annotation,
            "@CrossOrigin(allowCredentials=true) with wildcard/missing origins — restrict to specific trusted domains",
        )
    }
}
