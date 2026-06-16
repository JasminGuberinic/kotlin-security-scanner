package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PanacheRawQueryRuleTest {

    private val rule = PanacheRawQueryRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags find with interpolated query string`() {
        val code = """
            fun findByRole(role: String) = User.find("role = '${'$'}role'")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags list with interpolated query`() {
        val code = """
            fun listByStatus(status: String) = Order.list("status = '${'$'}status'")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags count with interpolated query`() {
        val code = """
            fun countActive(type: String) = Product.count("type = '${'$'}type' AND active = true")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags delete with interpolated query`() {
        val code = """
            fun deleteOld(status: String) = Session.delete("status = '${'$'}status'")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores find with positional parameter`() {
        val code = """
            fun findByRole(role: String) = User.find("role = ?1", role)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores find with literal query`() {
        val code = """
            fun findActive() = User.find("active = true")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores find with field shorthand`() {
        val code = """
            fun findByName(name: String) = User.find("name", name)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-string first argument like ID lookup`() {
        val code = """
            fun findById(id: Long) = User.findById(id)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on QuarkusPermitAllSensitive fixture`() {
        val code = """
            import javax.ws.rs.DELETE
            import javax.annotation.security.PermitAll
            class UserResource {
                @DELETE @PermitAll
                fun delete(): Response = Response.noContent().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
