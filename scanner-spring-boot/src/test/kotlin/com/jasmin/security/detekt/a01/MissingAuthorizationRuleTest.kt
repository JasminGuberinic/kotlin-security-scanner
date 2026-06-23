package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class MissingAuthorizationRuleTest {

    private val rule = MissingAuthorizationRule()

    @Test
    fun `flags GetMapping without security annotation`() {
        val code = """
            @GetMapping("/users")
            fun getUsers(): List<String> = emptyList()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags PostMapping without security annotation`() {
        val code = """
            @PostMapping("/users")
            fun createUser(): String = "ok"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags RequestMapping without security annotation`() {
        val code = """
            @RequestMapping("/admin")
            fun admin(): String = "ok"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores GetMapping with PreAuthorize`() {
        val code = """
            @GetMapping("/users")
            @PreAuthorize("hasRole('ADMIN')")
            fun getUsers(): List<String> = emptyList()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GetMapping with Secured`() {
        val code = """
            @GetMapping("/users")
            @Secured("ROLE_ADMIN")
            fun getUsers(): List<String> = emptyList()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores handler when class has PreAuthorize`() {
        val code = """
            @RestController
            @PreAuthorize("hasRole('A')")
            class C {
                @GetMapping("/x")
                fun x(): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores function with no endpoint annotation`() {
        val code = """
            fun helperFunction(): String = "ok"
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
