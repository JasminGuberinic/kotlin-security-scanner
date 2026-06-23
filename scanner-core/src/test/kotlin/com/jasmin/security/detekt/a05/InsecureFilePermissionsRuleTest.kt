package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureFilePermissionsRuleTest {

    private val rule = InsecureFilePermissionsRule(Config.empty)

    @Test
    fun `flags world-accessible posix permissions`() {
        val code = """
            import java.nio.file.attribute.PosixFilePermissions
            fun perms() = PosixFilePermissions.fromString("rwxrwxrwx")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setWritable for all users`() {
        val code = """
            import java.io.File
            fun open(file: File) { file.setWritable(true, false) }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores owner-only posix permissions`() {
        val code = """
            import java.nio.file.attribute.PosixFilePermissions
            fun perms() = PosixFilePermissions.fromString("rw-------")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setWritable for owner only`() {
        val code = """
            import java.io.File
            fun open(file: File) { file.setWritable(true, true) }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
