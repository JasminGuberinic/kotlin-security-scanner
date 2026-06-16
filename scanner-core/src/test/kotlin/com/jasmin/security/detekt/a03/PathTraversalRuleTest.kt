package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class PathTraversalRuleTest {

    private val rule = PathTraversalRule()

    @Test
    fun `flags File constructor with variable`() {
        val code = """
            fun readFile(userPath: String) = java.io.File(userPath)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags FileInputStream with variable`() {
        val code = """
            fun open(userPath: String) = java.io.FileInputStream(userPath)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags FileReader with variable`() {
        val code = """
            fun read(userPath: String) = java.io.FileReader(userPath)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags string template in File constructor`() {
        val code = """
            fun readFile(name: String) = java.io.File("/uploads/${'$'}name")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores File with string literal`() {
        val code = """
            val config = java.io.File("/etc/app/config.yml")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores File with no arguments`() {
        val code = """
            val dir = java.io.File(".")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag cipher patterns
    @Test
    fun `does not interfere with cipher code`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag sql injection patterns
    @Test
    fun `does not interfere with sql injection code`() {
        val code = """
            fun find(id: String) = "SELECT * FROM files WHERE id = ${'$'}id"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
