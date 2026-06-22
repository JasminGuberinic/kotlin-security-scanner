package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedPrivateKeyRuleTest {

    private val rule = HardcodedPrivateKeyRule(Config.empty)

    @Test
    fun `flags RSA private key PEM header`() {
        val code = """
            val pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags PKCS8 private key PEM header`() {
        val code = """
            val pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags EC private key PEM header`() {
        val code = """
            val ecKey = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg..."
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags OpenSSH private key PEM header`() {
        val code = """
            val sshKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1..."
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores public key PEM header`() {
        val code = """
            val publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores certificate PEM header`() {
        val code = """
            val cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWg..."
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores path to key file`() {
        val code = """
            val keyPath = "/etc/ssl/private/server.key"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
