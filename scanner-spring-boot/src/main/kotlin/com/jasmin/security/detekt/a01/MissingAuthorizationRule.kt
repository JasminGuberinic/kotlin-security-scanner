package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns.SPRING_ENDPOINT_ANNOTATIONS
import com.jasmin.security.detekt.core.DetectionPatterns.SPRING_SECURITY_ANNOTATIONS
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.psiUtil.getParentOfType

// FindSecBugs: SPRING_ENDPOINT — OWASP A01
class MissingAuthorizationRule(config: Config = Config.empty) : SecurityRule(config) {

    override val issue = Issue(
        id = "MissingAuthorization",
        severity = Severity.Security,
        description = "Spring endpoint has no authorization annotation — add @PreAuthorize or @Secured (OWASP A01)",
        debt = Debt.TWENTY_MINS
    )

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationNames()
        // A class-level @PreAuthorize/@Secured/@RolesAllowed applies to every handler in the class.
        val classAnnotations = function.getParentOfType<KtClass>(strict = true)?.annotationNames().orEmpty()
        if (isEndpoint(annotations) &&
            isMissingSecurityAnnotation(annotations) &&
            isMissingSecurityAnnotation(classAnnotations)
        ) {
            reportAt(function, "Function '${function.name}' is a Spring endpoint without @PreAuthorize or @Secured")
        }
    }

    private fun isEndpoint(annotations: Set<String>) =
        annotations.any { it in SPRING_ENDPOINT_ANNOTATIONS }

    private fun isMissingSecurityAnnotation(annotations: Set<String>) =
        annotations.none { it in SPRING_SECURITY_ANNOTATIONS }
}
