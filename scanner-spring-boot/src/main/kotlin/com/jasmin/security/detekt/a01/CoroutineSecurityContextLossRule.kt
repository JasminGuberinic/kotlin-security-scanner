package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A01 — Broken Access Control
 * Kotlin-unique: impossible to detect via JVM bytecode analysis.
 *
 * Spring Security's @PreAuthorize / @PostAuthorize annotations do not propagate
 * correctly to Kotlin coroutine functions. The security context is silently dropped
 * because coroutine desugaring creates a state machine class that the proxy intercept
 * mechanism does not instrument. The authorization check never runs.
 *
 * Reference: Spring Security GitHub issue #10810
 *
 * Compliant:
 *   // Use coroutineContext[SecurityContext] or reactor context bridging
 *   suspend fun getUser(): User = withSecurityContext { securityService.get() }
 *
 * Non-compliant:
 *   @PreAuthorize("hasRole('ADMIN')")
 *   suspend fun deleteUser(id: Long) { ... }  // annotation silently ignored
 */
class CoroutineSecurityContextLossRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "CoroutineSecurityContextLoss",
        severity = Severity.Security,
        description = "@PreAuthorize/@PostAuthorize on suspend fun — security context is silently dropped",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if (!function.hasModifier(KtTokens.SUSPEND_KEYWORD)) return
        val annotations = function.annotationEntries
            .mapNotNull { it.shortName?.asString() }.toSet()
        if (annotations.none { it in DetectionPatterns.SPRING_SECURITY_ANNOTATIONS }) return
        reportAt(
            function,
            "@PreAuthorize/@PostAuthorize on suspend fun is silently ignored — use coroutine-aware security context",
        )
    }
}
