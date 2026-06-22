package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorMultipartInsecureUploadRuleTest {

    private val rule = KtorMultipartInsecureUploadRule(Config.empty)

    @Test
    fun `flags receiveMultipart without size limit`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart()
                multipart.forEachPart { part -> part.dispose() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores receiveMultipart with maxFileSize`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart(maxFileSize = 10 * 1024 * 1024L)
                multipart.forEachPart { part -> part.dispose() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with permissive CORS code`() {
        val code = """
            fun Application.configureCors() {
                install(CORS) {
                    anyHost()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
