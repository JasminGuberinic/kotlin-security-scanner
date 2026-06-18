package com.jasmin.security.detekt.a10

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RestTemplateSsrfRuleTest {

    private val rule = RestTemplateSsrfRule(Config.empty)

    @Test
    fun `flags getForObject with interpolated url`() {
        val code = """
            class ApiClient(private val restTemplate: RestTemplate) {
                fun fetch(userId: String): String {
                    return restTemplate.getForObject("https://service/users/${'$'}userId", String::class.java)!!
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags getForEntity with variable url`() {
        val code = """
            class ApiClient(private val restTemplate: RestTemplate) {
                fun fetch(url: String): ResponseEntity<String> {
                    return restTemplate.getForEntity(url, String::class.java)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags exchange with variable url`() {
        val code = """
            class ApiClient(private val restTemplate: RestTemplate) {
                fun post(url: String, body: Any): ResponseEntity<String> {
                    return restTemplate.exchange(url, HttpMethod.POST, HttpEntity(body), String::class.java)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores getForObject with literal url`() {
        val code = """
            class ApiClient(private val restTemplate: RestTemplate) {
                fun fetch(): String {
                    return restTemplate.getForObject("https://api.trusted.com/data", String::class.java)!!
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with WebClient SSRF code`() {
        val code = """
            class ApiClient {
                fun fetch(url: String) = WebClient.create("https://api.trusted.com").get().retrieve()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
