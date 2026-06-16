package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class InsecureRandomRuleTest {

    private val rule = InsecureRandomRule()

    @Test
    fun `flags Random() constructor call`() {
        val code = """
            import java.util.Random
            fun token(): Int = Random().nextInt(100000)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ThreadLocalRandom call`() {
        val code = """
            import java.util.concurrent.ThreadLocalRandom
            fun token(): Int = ThreadLocalRandom().nextInt(100000)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores SecureRandom`() {
        val code = """
            import java.security.SecureRandom
            fun token(): Int = SecureRandom().nextInt(100000)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores kotlin random extension function`() {
        val code = """
            fun token(): Int = (1..100000).random()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag sql injection patterns
    @Test
    fun `does not interfere with sql injection code`() {
        val code = """
            fun find(id: String) = "SELECT * FROM items WHERE id = ${'$'}id"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
