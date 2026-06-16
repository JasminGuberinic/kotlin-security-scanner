package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class TrustAllCertsRuleTest {

    private val rule = TrustAllCertsRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags empty checkServerTrusted`() {
        val code = """
            import javax.net.ssl.X509TrustManager
            class NaiveTrustManager : X509TrustManager {
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) { }
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) { }
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(2)
    }

    @Test
    fun `flags empty checkClientTrusted only`() {
        val code = """
            import javax.net.ssl.X509TrustManager
            object AllowAll : X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
                    val trusted = listOf("trusted.example.com")
                }
                override fun getAcceptedIssuers() = emptyArray<java.security.cert.X509Certificate>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores checkServerTrusted with validation logic`() {
        val code = """
            import javax.net.ssl.X509TrustManager
            class PinningTrustManager : X509TrustManager {
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
                    val expected = "SHA256:abc123"
                    if (chain.isEmpty()) throw java.security.cert.CertificateException("empty chain")
                }
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers() = emptyArray<java.security.cert.X509Certificate>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores unrelated empty function`() {
        val code = """
            class Service {
                fun initialize() { }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on hardcoded IV fixture`() {
        val code = """
            import javax.crypto.spec.IvParameterSpec
            fun buildSpec() = IvParameterSpec(byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
