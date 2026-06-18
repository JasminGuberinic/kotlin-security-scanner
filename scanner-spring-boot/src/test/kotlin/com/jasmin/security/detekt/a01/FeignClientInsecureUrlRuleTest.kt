package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class FeignClientInsecureUrlRuleTest {

    private val rule = FeignClientInsecureUrlRule(Config.empty)

    @Test
    fun `flags FeignClient with http url`() {
        val code = """
            @FeignClient(name = "users", url = "http://user-service:8080")
            interface UserClient {
                fun getUser(id: Long): User
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores FeignClient with https url`() {
        val code = """
            @FeignClient(name = "users", url = "https://user-service:8080")
            interface UserClient {
                fun getUser(id: Long): User
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores FeignClient without url (service discovery)`() {
        val code = """
            @FeignClient(name = "users")
            interface UserClient {
                fun getUser(id: Long): User
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with missing authorization code`() {
        val code = """
            @RestController
            class UserController {
                @GetMapping("/users")
                fun getUsers() = listOf<String>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
