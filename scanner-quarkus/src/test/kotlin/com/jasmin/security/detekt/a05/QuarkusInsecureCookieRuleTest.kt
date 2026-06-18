package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusInsecureCookieRuleTest {

    private val rule = QuarkusInsecureCookieRule(Config.empty)

    @Test
    fun `flags NewCookie constructor without secure flags`() {
        val code = """
            fun setCookie(): Response {
                return Response.ok().cookie(NewCookie("SESSION", token)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags NewCookie_Builder without secure and httpOnly`() {
        val code = """
            fun setCookie(): Response {
                val cookie = NewCookie.Builder("SESSION").path("/").build()
                return Response.ok().cookie(cookie).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores NewCookie_Builder with secure and httpOnly`() {
        val code = """
            val cookie = NewCookie.Builder("SESSION").secure(true).httpOnly(true).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusCors fixture`() {
        val code = """
            quarkus.http.cors.origins=https://app.example.com
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
