package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CrossOriginCredentialsWildcardRuleTest {

    private val rule = CrossOriginCredentialsWildcardRule(Config.empty)

    @Test
    fun `flags CrossOrigin with wildcard origins and allowCredentials`() {
        val code = """
            @CrossOrigin(origins = ["*"], allowCredentials = "true")
            @RestController
            class UserController
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags CrossOrigin without origins and allowCredentials`() {
        val code = """
            @CrossOrigin(allowCredentials = "true")
            @GetMapping("/profile")
            fun getProfile(): UserDto = UserDto()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags CrossOrigin on method level`() {
        val code = """
            @RestController
            class ApiController {
                @CrossOrigin(origins = ["*"], allowCredentials = "true")
                @GetMapping("/data")
                fun getData() = emptyList<String>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores CrossOrigin with specific origin and allowCredentials`() {
        val code = """
            @CrossOrigin(origins = ["https://app.example.com"], allowCredentials = "true")
            @RestController
            class UserController
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores wildcard methods when origins is restricted`() {
        // The wildcard is in `methods`, not `origins`, so this must not be flagged.
        val code = """
            @CrossOrigin(origins = ["https://app.example.com"], methods = ["*"], allowCredentials = "true")
            @RestController
            class UserController
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores CrossOrigin without allowCredentials`() {
        val code = """
            @CrossOrigin(origins = ["*"])
            @RestController
            class UserController
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with permissive cors code`() {
        val code = """
            @Configuration
            class CorsConfig {
                fun corsConfigurer() = object : WebMvcConfigurer {
                    override fun addCorsMappings(registry: CorsRegistry) {
                        registry.addMapping("/**").allowedOrigins("*")
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
