package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class TrustAllHostnamesRuleTest {

    private val rule = TrustAllHostnamesRule(Config.empty)

    @Test
    fun `flags setDefaultHostnameVerifier with always-true lambda`() {
        val code = """
            import javax.net.ssl.HttpsURLConnection
            fun disableVerification() {
                HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setHostnameVerifier with always-true lambda`() {
        val code = """
            import javax.net.ssl.HttpsURLConnection
            fun disableVerification(conn: HttpsURLConnection) {
                conn.setHostnameVerifier { _, _ -> true }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores setDefaultHostnameVerifier with real verifier`() {
        val code = """
            import javax.net.ssl.HttpsURLConnection
            fun configure(allowed: Set<String>) {
                HttpsURLConnection.setDefaultHostnameVerifier { hostname, _ -> hostname in allowed }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setDefaultHostnameVerifier with multi-statement lambda`() {
        val code = """
            import javax.net.ssl.HttpsURLConnection
            fun configure() {
                HttpsURLConnection.setDefaultHostnameVerifier { hostname, session ->
                    val allowed = setOf("api.example.com")
                    hostname in allowed
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores other calls named setSomething`() {
        val code = """
            fun configure() {
                cache.setMaxSize(100)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
