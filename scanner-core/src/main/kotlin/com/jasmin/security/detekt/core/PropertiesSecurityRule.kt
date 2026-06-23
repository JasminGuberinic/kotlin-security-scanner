package com.jasmin.security.detekt.core

import io.github.detekt.psi.FilePath
import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Location
import io.gitlab.arturbosch.detekt.api.SourceLocation
import io.gitlab.arturbosch.detekt.api.TextLocation
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
 * (propertyKey, message) pair.
 *
 * The finding is reported **at the offending key's line in application.properties**
 * — not at the Kotlin file that happened to trigger the scan — so IDE and SARIF
 * annotations point developers to the real source of the problem.
 *
 * Unit-test approach: call [scanProperties] directly with a hand-crafted Properties
 * object — no filesystem access needed.
 */
abstract class PropertiesSecurityRule(config: Config) : SecurityRule(config) {

    // Backstop dedup if the same instance happens to visit the owner file twice.
    private val scannedRoots: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    // visitKtFile is the PSI visitor hook called when the tree walker reaches the root KtFile
    @Suppress("ReturnCount")
    final override fun visitKtFile(file: KtFile) {
        super.visitKtFile(file)
        val currentFilePath = file.virtualFile?.path ?: return
        val root = findProjectRoot(file) ?: return
        val propertiesFile = File(root, "src/main/resources/application.properties")
        if (!propertiesFile.exists()) return
        // Detekt creates a rule instance per file, so instance state cannot dedup across
        // files. Instead exactly one Kotlin file in the module "owns" the scan: the finding
        // is emitted once no matter how many files are visited or instances created — and
        // with no cross-run static state, so it stays correct under the Gradle daemon.
        if (!ownsScan(root, currentFilePath)) return
        if (!scannedRoots.add(root)) return
        val rawLines = propertiesFile.readLines()
        val props = Properties().also { p -> propertiesFile.bufferedReader().use { p.load(it) } }
        val cwe = CweMapping.forRule(issue.id)
        val fix = RemediationHints.forRule(issue.id)
        val filePath = FilePath.fromAbsolute(propertiesFile.toPath())
        scanProperties(props).forEach { (key, message) ->
            val withCwe = "application.properties[$key]: $message" + if (cwe != null) " [$cwe]" else ""
            val fullMessage = if (fix != null) "$withCwe — Fix: $fix" else withCwe
            report(CodeSmell(issue, propertiesEntity(key, rawLines, filePath), fullMessage))
        }
    }

    /**
     * Analyse the properties and return all detected (propertyKey, message) pairs.
     * Return an empty list if no issues are found.
     */
    abstract fun scanProperties(props: Properties): List<Pair<String, String>>

    /** Build an Entity that points at [key]'s line in the properties file. */
    private fun propertiesEntity(key: String, rawLines: List<String>, filePath: FilePath): Entity {
        val (lineNumber, startOffset) = locateKey(key, rawLines)
        val location = Location(
            SourceLocation(lineNumber, 1),
            TextLocation(startOffset, startOffset + key.length),
            filePath,
        )
        return Entity("application.properties", key, location)
    }

    /**
     * Find the 1-based line and character offset where [key] is declared.
     * Matches the key only when followed by a separator (= : whitespace) so that a
     * prefix such as "quarkus.http.cors" does not match "quarkus.http.cors.origins".
     * Falls back to line 1 / offset 0 when the key is not found in the raw text.
     */
    @Suppress("ReturnCount")
    private fun locateKey(key: String, rawLines: List<String>): Pair<Int, Int> {
        var offset = 0
        rawLines.forEachIndexed { index, line ->
            val trimmed = line.trimStart()
            if (trimmed.startsWith(key)) {
                val after = trimmed.getOrNull(key.length)
                if (after == null || after == '=' || after == ':' || after == ' ' || after == '\t') {
                    val leadingWhitespace = line.length - trimmed.length
                    return (index + 1) to (offset + leadingWhitespace)
                }
            }
            offset += line.length + 1 // +1 for the newline consumed by readLines()
        }
        return 1 to 0
    }

    /**
     * True when [currentFilePath] is the single Kotlin file responsible for scanning this
     * module's properties — the lexicographically smallest .kt path under src/main/kotlin.
     * Guarantees each properties finding is reported exactly once per module.
     */
    private fun ownsScan(root: String, currentFilePath: String): Boolean {
        val sourceDir = File(root, "src/main/kotlin")
        if (!sourceDir.isDirectory) return true // non-standard layout: let any file own it
        val owner = sourceDir.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .map { it.absolutePath }
            .minOrNull()
            ?: return true
        return File(currentFilePath).absolutePath == owner
    }

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
