package com.jasmin.security.detekt.core

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Rule
import org.jetbrains.kotlin.psi.KtAnnotated
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtElement
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * Base class for all custom security rules.
 *
 * Provides small, named helpers so rule logic reads declaratively —
 * describing WHAT is checked rather than HOW the AST is traversed.
 * Keep this lean: only add a helper when two or more rules share the need.
 */
abstract class SecurityRule(config: Config) : Rule(config) {

    // ── Reporting ─────────────────────────────────────────────────────────────

    protected fun reportAt(node: KtElement, message: String) {
        val cwe = CweMapping.forRule(issue.id)
        val fix = RemediationHints.forRule(issue.id)
        val withCwe = if (cwe != null) "$message [$cwe]" else message
        val fullMessage = if (fix != null) "$withCwe — Fix: $fix" else withCwe
        report(CodeSmell(issue, Entity.from(node), fullMessage))
    }

    // ── AST traversal ─────────────────────────────────────────────────────────

    /** Walk up [levels] parent steps and return that ancestor (or null). */
    protected fun KtElement.ancestor(levels: Int): KtElement? {
        var current: KtElement? = this
        repeat(levels) { current = current?.parent as? KtElement }
        return current
    }

    /** True when this string contains no interpolated expressions. */
    protected fun KtStringTemplateExpression.isLiteral(): Boolean = !hasInterpolation()

    /** Raw string value without surrounding quotes. */
    protected fun KtStringTemplateExpression.rawValue(): String =
        text.removeSurrounding("\"").removeSurrounding("'")

    // ── Annotation inspection ─────────────────────────────────────────────────

    /** Short name of each annotation on this element (e.g. "GetMapping"). */
    protected fun KtAnnotated.annotationNames(): Set<String> =
        annotationEntries.mapNotNull { it.shortName() }.toSet()

    private fun KtAnnotationEntry.shortName(): String? =
        shortName?.asString()
}
