package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecurePasswordEncoderRuleTest {

    private val rule = InsecurePasswordEncoderRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags NoOpPasswordEncoder getInstance`() {
        val code = """
            import org.springframework.security.crypto.password.NoOpPasswordEncoder
            fun encoder() = NoOpPasswordEncoder.getInstance()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Md5PasswordEncoder constructor`() {
        val code = """
            import org.springframework.security.authentication.encoding.Md5PasswordEncoder
            fun encoder() = Md5PasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ShaPasswordEncoder constructor`() {
        val code = """
            import org.springframework.security.authentication.encoding.ShaPasswordEncoder
            fun encoder() = ShaPasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags LdapShaPasswordEncoder constructor`() {
        val code = """
            import org.springframework.security.crypto.password.LdapShaPasswordEncoder
            fun encoder() = LdapShaPasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores BCryptPasswordEncoder`() {
        val code = """
            import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
            fun encoder() = BCryptPasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Argon2PasswordEncoder`() {
        val code = """
            import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
            fun encoder() = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores SCryptPasswordEncoder`() {
        val code = """
            import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
            fun encoder() = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SpEL injection fixture`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun eval(userExpr: String): Any? =
                SpelExpressionParser().parseExpression(userExpr).getValue()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
