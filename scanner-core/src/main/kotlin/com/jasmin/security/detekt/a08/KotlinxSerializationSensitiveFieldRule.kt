package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass

/**
 * OWASP A08 — Software and Data Integrity Failures
 *
 * A @Serializable class whose primary-constructor parameter name matches a
 * sensitive keyword (password, secret, private_key…) will have that field
 * included in every JSON/CBOR/Protobuf serialization unless annotated with
 * @Transient. This can expose secrets in API responses, logs, or cache stores.
 *
 * Compliant:
 *   @Serializable data class User(val username: String, @Transient val password: String = "")
 *
 * Non-compliant:
 *   @Serializable data class User(val username: String, val password: String)
 */
class KotlinxSerializationSensitiveFieldRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "KotlinxSerializationSensitiveField",
        severity = Severity.Security,
        description = "@Serializable class has sensitive field without @Transient — will be serialized",
        debt = Debt.TWENTY_MINS,
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        if (DetectionPatterns.KOTLINX_SERIALIZABLE_ANNOTATION !in klass.annotationNames()) return
        klass.primaryConstructorParameters.forEach { param ->
            val name = param.name?.lowercase() ?: return@forEach
            if (DetectionPatterns.SERIALIZATION_SENSITIVE_FIELDS.none { it in name }) return@forEach
            if (DetectionPatterns.KOTLINX_TRANSIENT_ANNOTATION in param.annotationNames()) return@forEach
            reportAt(
                param,
                "@Serializable field '${param.name}' is sensitive — add @Transient to exclude from serialization",
            )
        }
        klass.getProperties().forEach { prop ->
            val name = prop.name?.lowercase() ?: return@forEach
            if (DetectionPatterns.SERIALIZATION_SENSITIVE_FIELDS.none { it in name }) return@forEach
            if (DetectionPatterns.KOTLINX_TRANSIENT_ANNOTATION in prop.annotationNames()) return@forEach
            reportAt(
                prop,
                "@Serializable field '${prop.name}' is sensitive — add @Transient to exclude from serialization",
            )
        }
    }
}
