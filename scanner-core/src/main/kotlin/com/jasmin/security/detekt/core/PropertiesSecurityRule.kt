package com.jasmin.security.detekt.core

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Entity
import org.jetbrains.kotlin.psi.KtFile
import java.io.File
import java.util.Collections
import java.util.Properties

/**
 * Base class for rules that scan application.properties alongside Kotlin sources.
 *
 * On the first Kotlin file visited whose project root contains
 * src/main/resources/application.properties, the rule calls [scanProperties]
 * with the parsed Properties object. Each detected issue should be returned as a
 * (propertyKey, message) pair — the base class turns them into Detekt findings
 * reported at the file level with a clear "application.properties[key]:" prefix.
 *
 * Unit-test approach: call [scanProperties] directly with a hand-crafted Properties
 * object — no filesystem access needed.
 */
abstract class PropertiesSecurityRule(config: Config) : SecurityRule(config) {

    // Each rule instance tracks its own scanned roots so that multiple
    // PropertiesSecurityRules in the same Detekt run each scan the file independently.
    private val scannedRoots: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    // visitKtFile is the PSI visitor hook called when the tree walker reaches the root KtFile
    @Suppress("ReturnCount")
    final override fun visitKtFile(file: KtFile) {
        super.visitKtFile(file)
        val root = findProjectRoot(file) ?: return
        if (!scannedRoots.add(root)) return
        val propertiesFile = File(root, "src/main/resources/application.properties")
        if (!propertiesFile.exists()) return
        val props = Properties().also { it.load(propertiesFile.bufferedReader()) }
        val cwe = CweMapping.forRule(issue.id)
        val fix = RemediationHints.forRule(issue.id)
        scanProperties(props).forEach { (key, message) ->
            val withCwe = "application.properties[$key]: $message" + if (cwe != null) " [$cwe]" else ""
            val fullMessage = if (fix != null) "$withCwe — Fix: $fix" else withCwe
            report(CodeSmell(issue, Entity.from(file), fullMessage))
        }
    }

    /**
     * Analyse the properties and return all detected (propertyKey, message) pairs.
     * Return an empty list if no issues are found.
     */
    abstract fun scanProperties(props: Properties): List<Pair<String, String>>

    @Suppress("ReturnCount")
    private fun findProjectRoot(file: KtFile): String? {
        var dir = File(file.virtualFile?.path ?: return null).parentFile
        while (dir != null) {
            if (
                File(dir, "build.gradle.kts").exists() ||
                File(dir, "settings.gradle.kts").exists()
            ) {
                return dir.absolutePath
            }
            dir = dir.parentFile
        }
        return null
    }
}
