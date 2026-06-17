package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KotlinxSerializationSensitiveFieldRuleTest {

    private val rule = KotlinxSerializationSensitiveFieldRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Serializable data class with password field`() {
        val code = """
            @Serializable
            data class UserDto(val username: String, val password: String)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Serializable data class with secret field`() {
        val code = """
            @Serializable
            data class Config(val endpoint: String, val secret: String)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Serializable class with private_key body property`() {
        val code = """
            @Serializable
            class KeyHolder {
                var private_key: String = ""
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores password field annotated with Transient`() {
        val code = """
            @Serializable
            data class UserDto(val username: String, @Transient val password: String = "")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-Serializable class with sensitive field`() {
        val code = """
            data class InternalUser(val username: String, val password: String)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Serializable class with non-sensitive fields`() {
        val code = """
            @Serializable
            data class UserDto(val username: String, val email: String)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on JacksonUnsafeDeserialization fixture`() {
        val code = """
            fun configure(mapper: ObjectMapper) {
                mapper.enableDefaultTyping()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
