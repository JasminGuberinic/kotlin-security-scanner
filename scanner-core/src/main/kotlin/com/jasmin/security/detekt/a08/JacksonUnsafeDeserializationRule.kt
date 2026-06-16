package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A08 — Software and Data Integrity Failures
 * FindSecBugs: JACKSON_UNSAFE_DESERIALIZATION
 *
 * Enabling polymorphic type handling in Jackson without a validator
 * allows an attacker to deserialize arbitrary classes, leading to RCE.
 * CVE-2017-7525, CVE-2019-14379, CVE-2020-35728 all exploit this pattern.
 *
 * Compliant:
 *   @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)          // named subtypes only
 *   mapper.setPolymorphicTypeValidator(validator)       // allowlist-based
 *
 * Non-compliant:
 *   mapper.enableDefaultTyping()
 *   @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
 */
class JacksonUnsafeDeserializationRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "JacksonUnsafeDeserialization",
        severity = Severity.Security,
        description = "Jackson default typing or Id.CLASS enables arbitrary type deserialization — RCE risk",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.JACKSON_UNSAFE_TYPING_METHODS) return
        reportAt(
            expression,
            "$callee() enables polymorphic type handling — use setPolymorphicTypeValidator() with an allowlist",
        )
    }

    @Suppress("ReturnCount")
    override fun visitAnnotationEntry(annotationEntry: KtAnnotationEntry) {
        super.visitAnnotationEntry(annotationEntry)
        if (annotationEntry.shortName?.asString() != DetectionPatterns.JACKSON_TYPE_INFO_ANNOTATION) return
        val useArg = annotationEntry.valueArgumentList?.arguments
            ?.firstOrNull { it.text.substringBefore("=").trim() == "use" }
            ?.getArgumentExpression()?.text ?: return
        if ("CLASS" !in useArg && "MINIMAL_CLASS" !in useArg) return
        reportAt(
            annotationEntry,
            "@JsonTypeInfo(use=Id.CLASS) deserializes arbitrary types — use Id.NAME with named subtypes",
        )
    }
}
