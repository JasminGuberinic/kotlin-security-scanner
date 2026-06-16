package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedIvRuleTest {

    private val rule = HardcodedIvRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags IvParameterSpec with literal byteArrayOf`() {
        val code = """
            import javax.crypto.spec.IvParameterSpec
            fun buildSpec() = IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags IvParameterSpec with hex byteArrayOf`() {
        val code = """
            import javax.crypto.spec.IvParameterSpec
            val FIXED_IV = IvParameterSpec(byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores IvParameterSpec with variable argument`() {
        val code = """
            import javax.crypto.spec.IvParameterSpec
            import java.security.SecureRandom
            fun buildSpec(): IvParameterSpec {
                val iv = ByteArray(16)
                SecureRandom().nextBytes(iv)
                return IvParameterSpec(iv)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores IvParameterSpec with empty byteArrayOf`() {
        val code = """
            import javax.crypto.spec.IvParameterSpec
            fun empty() = IvParameterSpec(byteArrayOf())
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated constructor calls`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            fun buildKey(bytes: ByteArray) = SecretKeySpec(byteArrayOf(1, 2, 3), "AES")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on TrustAllCerts fixture`() {
        val code = """
            import javax.net.ssl.X509TrustManager
            class NaiveTM : X509TrustManager {
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers() = emptyArray<java.security.cert.X509Certificate>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
