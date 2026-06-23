package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ZipSlipRuleTest {

    private val rule = ZipSlipRule(Config.empty)

    @Test
    fun `flags File built from a zip entry name`() {
        val code = """
            import java.io.File
            import java.util.zip.ZipEntry
            fun extract(dir: File, entry: ZipEntry) = File(dir, entry.name)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags resolve with a zipEntry name`() {
        val code = """
            import java.nio.file.Path
            import java.util.zip.ZipEntry
            fun extract(dir: Path, zipEntry: ZipEntry) = dir.resolve(zipEntry.name)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores File built from a constant name`() {
        val code = """
            import java.io.File
            fun output(dir: File) = File(dir, "output.txt")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores a name property from an unrelated receiver`() {
        val code = """
            import java.io.File
            data class User(val name: String)
            fun userFile(dir: File, user: User) = File(dir, user.name)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
