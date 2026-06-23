package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautInsecureCookieRuleTest {

    private val rule = MicronautInsecureCookieRule(Config.empty)

    @Test
    fun `flags Cookie secure false`() {
        val code = """
            import io.micronaut.http.cookie.Cookie
            fun build(id: String) = Cookie.of("SESSION", id).secure(false)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Cookie secure true`() {
        val code = """
            import io.micronaut.http.cookie.Cookie
            fun build(id: String) = Cookie.of("SESSION", id).secure(true)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores secure false on a non-cookie builder`() {
        val code = """
            class ConnectionBuilder { fun secure(flag: Boolean) = this }
            fun build() = ConnectionBuilder().secure(false)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
