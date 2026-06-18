package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A01 — Broken Access Control
 *
 * Spring Security stores authentication in a ThreadLocal. Methods annotated with
 * @Async run on a different thread — SecurityContextHolder.getContext() returns
 * null (or the wrong principal) unless the executor is wrapped with
 * DelegatingSecurityContextAsyncTaskExecutor.
 *
 * Compliant:
 *   @Bean fun asyncExecutor() =
 *       DelegatingSecurityContextAsyncTaskExecutor(ThreadPoolTaskExecutor())
 *
 * Non-compliant:
 *   @Async
 *   fun process() { val auth = SecurityContextHolder.getContext().authentication }
 */
class AsyncSecurityContextLossRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "AsyncSecurityContextLoss",
        severity = Severity.Security,
        description = "@Async method reads SecurityContextHolder — context is lost across thread boundaries",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if ("Async" !in function.annotationNames()) return
        val body = function.bodyExpression?.text ?: return
        if ("SecurityContextHolder" !in body) return
        reportAt(
            function,
            "@Async method accesses SecurityContextHolder — security context is not propagated to async threads",
        )
    }
}
