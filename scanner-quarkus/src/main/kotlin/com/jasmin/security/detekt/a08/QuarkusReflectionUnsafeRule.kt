package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A08 — Software and Data Integrity (Deserialization Gadget via Reflection)
 * FindSecBugs: OBJECT_DESERIALIZATION
 *
 * Flags classes annotated with @RegisterForReflection that also implement Serializable
 * and override readObject(). Registering such a class for native-image reflection makes
 * it accessible to untrusted deserialisation gadget chains at runtime.
 *
 * Compliant:
 *   @RegisterForReflection
 *   class SafeDto(val name: String)   // no Serializable + readObject
 *
 * Non-compliant:
 *   @RegisterForReflection
 *   class RiskyClass : Serializable {
 *       @Throws(IOException::class)
 *       private fun readObject(stream: ObjectInputStream) { ... }
 *   }
 */
class QuarkusReflectionUnsafeRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "QuarkusReflectionUnsafe",
        severity = Severity.Security,
        description = "@RegisterForReflection on Serializable with readObject — deserialization gadget risk",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount")
    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        if (!hasRegisterForReflection(klass)) return
        if (!implementsSerializable(klass)) return
        if (!hasReadObjectMethod(klass)) return
        reportAt(
            klass,
            "@RegisterForReflection + Serializable with readObject — deserialization gadget, review reflection",
        )
    }

    private fun hasRegisterForReflection(klass: KtClass) =
        klass.annotationEntries.any { it.shortName?.asString() == DetectionPatterns.REGISTER_FOR_REFLECTION }

    private fun implementsSerializable(klass: KtClass) =
        klass.superTypeListEntries.any { it.text.contains("Serializable") }

    private fun hasReadObjectMethod(klass: KtClass) =
        klass.declarations.filterIsInstance<KtNamedFunction>().any { it.name == "readObject" }
}
