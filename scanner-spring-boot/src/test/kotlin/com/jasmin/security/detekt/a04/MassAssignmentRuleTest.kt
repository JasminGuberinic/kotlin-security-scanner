package com.jasmin.security.detekt.a04

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MassAssignmentRuleTest {

    private val rule = MassAssignmentRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags RequestBody bound to Entity class in same file`() {
        val code = """
            import javax.persistence.Entity
            import org.springframework.web.bind.annotation.*

            @Entity
            data class User(var id: Long = 0, var name: String = "", var role: String = "user")

            @RestController
            class UserController {
                @PostMapping("/users")
                fun create(@RequestBody user: User): User = user
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags RequestBody bound to Document class`() {
        val code = """
            import org.springframework.data.mongodb.core.mapping.Document
            import org.springframework.web.bind.annotation.*

            @Document
            data class Product(var id: String = "", var price: Double = 0.0)

            @RestController
            class ProductController {
                @PutMapping("/products")
                fun update(@RequestBody product: Product): Product = product
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags RequestBody bound to nullable Entity type`() {
        // Type normalization strips the nullability marker so `User?` resolves to `User`.
        val code = """
            import javax.persistence.Entity
            import org.springframework.web.bind.annotation.*

            @Entity
            data class User(var id: Long = 0, var name: String = "")

            @RestController
            class UserController {
                @PostMapping("/users")
                fun create(@RequestBody user: User?): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores RequestBody bound to DTO`() {
        val code = """
            import org.springframework.web.bind.annotation.*
            data class CreateUserRequest(val name: String, val email: String)

            @RestController
            class UserController {
                @PostMapping("/users")
                fun create(@RequestBody request: CreateUserRequest): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores RequestBody when entity class not in same file`() {
        val code = """
            import org.springframework.web.bind.annotation.*
            @RestController
            class OrderController {
                @PostMapping("/orders")
                fun create(@RequestBody order: Order): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores parameter without RequestBody`() {
        val code = """
            import javax.persistence.Entity
            @Entity data class User(var id: Long = 0, var name: String = "")
            class UserService {
                fun save(user: User): User = user
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on open redirect fixture`() {
        val code = """
            @Controller
            class AuthController {
                fun login(next: String): String = "redirect:" + next
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
