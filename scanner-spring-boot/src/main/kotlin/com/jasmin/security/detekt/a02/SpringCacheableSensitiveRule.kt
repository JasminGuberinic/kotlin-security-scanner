package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A02 — Cryptographic Failures (Sensitive data caching)
 *
 * @Cacheable on methods that return passwords, tokens, or credentials stores
 * sensitive data in an in-memory or distributed cache. Cache eviction policies
 * may never run, leaving credentials accessible to anyone with cache access.
 *
 * Compliant:
 *   @Cacheable("users")
 *   fun getUser(id: Long): UserDto
 *
 * Non-compliant:
 *   @Cacheable("tokens")
 *   fun getAccessToken(userId: Long): String
 */
class SpringCacheableSensitiveRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "SpringCacheableSensitive",
        severity = Severity.Security,
        description = "@Cacheable on security-sensitive method — credentials/tokens may persist in cache",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if ("Cacheable" !in function.annotationNames()) return
        val nameLower = function.name?.lowercase() ?: return
        val isSensitive = DetectionPatterns.SENSITIVE_LOG_KEYWORDS.any { it in nameLower }
        if (!isSensitive) return
        reportAt(function, "@Cacheable on sensitive method — remove caching or encrypt cached value")
    }
}
