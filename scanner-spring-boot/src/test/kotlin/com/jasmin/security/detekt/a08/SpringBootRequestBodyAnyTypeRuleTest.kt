package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringBootRequestBodyAnyTypeRuleTest {

    private val rule = SpringBootRequestBodyAnyTypeRule(Config.empty)

    @Test
    fun `flags @RequestBody Any`() {
        val code = """
            @PostMapping("/update")
            fun update(@RequestBody body: Any): ResponseEntity<Void> {
                process(body)
                return ResponseEntity.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @RequestBody Serializable`() {
        val code = """
            @PostMapping("/receive")
            fun receive(@RequestBody payload: Serializable): ResponseEntity<Void> {
                return ResponseEntity.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @RequestBody with concrete DTO type`() {
        val code = """
            @PostMapping("/update")
            fun update(@RequestBody dto: UpdateRequest): ResponseEntity<Void> {
                service.update(dto)
                return ResponseEntity.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @RequestBody String`() {
        val code = """
            @PostMapping("/raw")
            fun raw(@RequestBody body: String): ResponseEntity<String> {
                return ResponseEntity.ok(body.reversed())
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with MassAssignment fixture`() {
        val code = """
            @PostMapping("/users")
            fun createUser(@ModelAttribute user: User): User {
                return userService.create(user)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
