package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class LdapInjectionRuleTest {

    private val rule = LdapInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags search with interpolated filter`() {
        val code = """
            fun findUser(username: String) {
                ctx.search("ou=users,dc=example,dc=com", "(uid=${'$'}username)", controls)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags bind with interpolated dn`() {
        val code = """
            fun authenticate(user: String, pass: String) {
                ctx.bind("uid=${'$'}user,ou=users,dc=example,dc=com", null, null)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags lookup with interpolated name`() {
        val code = """
            fun lookup(cn: String): Any {
                return ctx.lookup("cn=${'$'}cn,ou=groups")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores search with literal filter`() {
        val code = """
            fun findAdmins() {
                ctx.search("ou=users", "(role=admin)", controls)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores search with parameterised filter`() {
        val code = """
            fun findUser(username: String) {
                val filter = "(uid={0})"
                ctx.search("ou=users", filter, arrayOf(username), controls)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated search call`() {
        val code = """
            fun find(query: String): List<String> {
                return index.search(query)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on command injection fixture`() {
        val code = """
            fun run(arg: String) {
                Runtime.getRuntime().exec("ls ${'$'}arg")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
