package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringBootInsecureFileUploadRuleTest {

    private val rule = SpringBootInsecureFileUploadRule(Config.empty)

    @Test
    fun `flags MultipartFile function using originalFilename in transferTo`() {
        val code = """
            fun upload(file: MultipartFile) {
                file.transferTo(File(file.originalFilename!!))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags MultipartFile function using originalFilename in Paths_get`() {
        val code = """
            fun upload(file: MultipartFile) {
                val dest = Paths.get(uploadDir, file.originalFilename)
                file.transferTo(dest)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores MultipartFile function that does not use originalFilename`() {
        val code = """
            fun upload(file: MultipartFile) {
                val safe = "${'$'}{UUID.randomUUID()}.pdf"
                file.transferTo(File(uploadDir, safe))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-multipart function`() {
        val code = """
            fun readFile(path: String): String {
                return File(path).readText()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with SpringCsrf fixture`() {
        val code = """
            fun securityConfig(http: HttpSecurity) {
                http.csrf { it.disable() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
