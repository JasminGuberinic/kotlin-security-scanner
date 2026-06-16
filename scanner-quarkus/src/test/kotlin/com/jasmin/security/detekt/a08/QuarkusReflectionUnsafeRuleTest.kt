package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusReflectionUnsafeRuleTest {

    private val rule = QuarkusReflectionUnsafeRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags RegisterForReflection on Serializable with readObject`() {
        val code = """
            import io.quarkus.runtime.annotations.RegisterForReflection
            import java.io.Serializable
            @RegisterForReflection
            class RiskyEntity : Serializable {
                private fun readObject(stream: java.io.ObjectInputStream) {
                    stream.defaultReadObject()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags RegisterForReflection on Serializable subtype with readObject`() {
        val code = """
            import io.quarkus.runtime.annotations.RegisterForReflection
            @RegisterForReflection
            class GadgetClass : java.io.Serializable {
                @Throws(java.io.IOException::class)
                private fun readObject(ois: java.io.ObjectInputStream) {
                    ois.defaultReadObject()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores RegisterForReflection without Serializable`() {
        val code = """
            import io.quarkus.runtime.annotations.RegisterForReflection
            @RegisterForReflection
            class SafeDto(val name: String, val email: String)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Serializable without RegisterForReflection`() {
        val code = """
            import java.io.Serializable
            class LegacyEntity : Serializable {
                private fun readObject(stream: java.io.ObjectInputStream) {
                    stream.defaultReadObject()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores RegisterForReflection on Serializable without readObject`() {
        val code = """
            import io.quarkus.runtime.annotations.RegisterForReflection
            import java.io.Serializable
            @RegisterForReflection
            class SafeSerializable(val id: Long) : Serializable
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on PanacheRawQuery fixture`() {
        val code = """
            fun findUsers(role: String) = User.find("role = '${'$'}role'")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
