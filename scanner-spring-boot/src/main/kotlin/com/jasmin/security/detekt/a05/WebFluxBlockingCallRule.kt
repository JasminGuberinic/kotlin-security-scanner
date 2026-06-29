package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.psiUtil.getStrictParentOfType

/**
 * OWASP A05 — Security Misconfiguration (Uncontrolled Resource Consumption / CWE-400)
 *
 * Calling `.block()` / `.blockFirst()` / `.blockLast()` inside a function that returns a
 * reactive type (`Mono`/`Flux`) blocks one of the few Netty event-loop threads. Under load
 * this starves the server and turns into a denial of service. Compose reactively
 * (`flatMap`, `zipWith`, …) instead of blocking.
 *
 * Non-compliant:
 *   fun handler(): Mono<User> {
 *       val user = userRepo.findById(id).block()   // blocks the event loop
 *       return Mono.just(user)
 *   }
 */
class WebFluxBlockingCallRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "WebFluxBlockingCall",
        severity = Severity.Security,
        description = "Blocking call (block()/blockFirst()/blockLast()) inside a reactive method — starves the event loop",
        debt = Debt.TWENTY_MINS,
    )

    private val blockingCalls = setOf("block", "blockFirst", "blockLast", "blockOptional")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text?.substringAfterLast(".") ?: return
        if (callee !in blockingCalls) return
        // Only flag when we're inside a reactive method (returns Mono/Flux).
        val returnType = expression.getStrictParentOfType<KtNamedFunction>()?.typeReference?.text ?: return
        if (!returnType.contains("Mono") && !returnType.contains("Flux")) return
        reportAt(
            expression,
            "$callee() blocks the event loop inside a reactive method — compose with flatMap/zipWith instead",
        )
    }
}
