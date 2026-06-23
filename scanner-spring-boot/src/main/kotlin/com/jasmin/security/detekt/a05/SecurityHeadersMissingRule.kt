package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A05 — Security Misconfiguration
 *
 * A SecurityFilterChain bean that never calls .headers { } leaves the
 * application without X-Frame-Options (clickjacking), Content-Security-Policy
 * (XSS), and other browser-enforced defences.
 *
 * Compliant:
 *   http.headers { frameOptions { deny() }; contentSecurityPolicy { ... } }
 *
 * Non-compliant:
 *   @Bean fun filterChain(http: HttpSecurity): SecurityFilterChain {
 *       http.authorizeHttpRequests { it.anyRequest().authenticated() }
 *       return http.build()
 *   }
 */
class SecurityHeadersMissingRule(config: Config) : SecurityRule(config) {

    private val HEADERS_CONFIG = Regex("""\.headers\s*[({]""")

    override val issue = Issue(
        id = "SecurityHeadersMissing",
        severity = Severity.Security,
        description = "SecurityFilterChain without HTTP security headers (X-Frame-Options, CSP…)",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if ("Bean" !in function.annotationNames()) return
        val returnType = function.typeReference?.text ?: return
        if ("SecurityFilterChain" !in returnType) return
        val body = function.bodyExpression?.text ?: return
        // Require an actual headers config call (.headers { } or .headers(...)), not just the
        // substring "headers" appearing somewhere (e.g. a variable name or comment).
        if (HEADERS_CONFIG.containsMatchIn(body)) return
        reportAt(
            function,
            "SecurityFilterChain has no .headers{} block — add frameOptions, contentSecurityPolicy, hsts",
        )
    }
}
