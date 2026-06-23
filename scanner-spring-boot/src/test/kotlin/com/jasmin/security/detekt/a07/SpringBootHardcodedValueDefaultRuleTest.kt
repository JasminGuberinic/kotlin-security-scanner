package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringBootHardcodedValueDefaultRuleTest {

    private val rule = SpringBootHardcodedValueDefaultRule(Config.empty)

    @Test
    fun `flags @Value with hardcoded secret default`() {
        val code = """
            @Value("\${'$'}{jwt.secret:-my-hardcoded-secret}")
            lateinit var jwtSecret: String
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @Value with hardcoded password default`() {
        val code = """
            @Value("\${'$'}{db.password:-changeit}")
            lateinit var dbPassword: String
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @Value with single-colon Spring default for secret`() {
        // Spring's real default syntax uses a single colon, not ':-' (bash).
        val code = """
            @Value("\${'$'}{jwt.secret:changeme}")
            lateinit var jwtSecret: String
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @Value with single colon but no default after it`() {
        val code = """
            @Value("\${'$'}{jwt.secret}")
            lateinit var jwtSecret: String
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @Value without default`() {
        val code = """
            @Value("\${'$'}{jwt.secret}")
            lateinit var jwtSecret: String
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @Value with non-sensitive default`() {
        val code = """
            @Value("\${'$'}{server.port:-8080}")
            var serverPort: Int = 8080
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with regular annotation usage`() {
        val code = """
            @Bean
            fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
