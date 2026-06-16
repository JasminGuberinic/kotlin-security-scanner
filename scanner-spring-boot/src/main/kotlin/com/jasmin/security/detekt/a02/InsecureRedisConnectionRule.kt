package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: UNENCRYPTED_SOCKET
 *
 * Spring Data Redis connection factories default to plaintext connections.
 * Session data, cached credentials, and Pub/Sub messages are transmitted
 * without encryption unless SSL is explicitly configured.
 *
 * Compliant:
 *   RedisStandaloneConfiguration("host", 6380).also { it.useSsl() }
 *   LettuceClientConfiguration.builder().useSsl().build()
 *
 * Non-compliant:
 *   RedisStandaloneConfiguration("redis.internal", 6379)
 */
class InsecureRedisConnectionRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureRedisConnection",
        severity = Severity.Security,
        description = "Redis connection without TLS — configure SSL via useSsl() or RedisSSLContext",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text !in DetectionPatterns.REDIS_CONNECTION_CONSTRUCTORS) return
        reportAt(
            expression,
            "Redis connection without TLS — enable SSL via LettuceClientConfiguration.builder().useSsl()",
        )
    }
}
