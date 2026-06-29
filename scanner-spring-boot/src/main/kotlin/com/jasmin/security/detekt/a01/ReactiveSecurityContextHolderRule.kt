package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.psiUtil.getStrictParentOfType

/**
 * OWASP A01 — Broken Access Control (Incorrect Authorization / CWE-863)
 *
 * In Spring WebFlux the SecurityContext lives in the Reactor Context, not in a ThreadLocal.
 * Calling the blocking `SecurityContextHolder.getContext()` inside a reactive handler returns
 * an empty context, so the current user is `null` and authorization checks silently misbehave.
 * Use `ReactiveSecurityContextHolder.getContext()` instead.
 *
 * Non-compliant:
 *   fun me(): Mono<String> {
 *       val auth = SecurityContextHolder.getContext().authentication   // empty in WebFlux
 *       return Mono.just(auth.name)
 *   }
 */
class ReactiveSecurityContextHolderRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "ReactiveSecurityContextHolder",
        severity = Severity.Security,
        description = "ThreadLocal SecurityContextHolder used in reactive code — returns empty; use ReactiveSecurityContextHolder",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text?.substringAfterLast(".") != "getContext") return
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        if (receiver.substringAfterLast(".") != "SecurityContextHolder") return
        // Only a problem in reactive code — enclosing function returns Mono/Flux.
        val returnType = expression.getStrictParentOfType<KtNamedFunction>()?.typeReference?.text ?: return
        if (!returnType.contains("Mono") && !returnType.contains("Flux")) return
        reportAt(
            expression,
            "SecurityContextHolder.getContext() is empty in WebFlux — use ReactiveSecurityContextHolder.getContext()",
        )
    }
}
