package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedAesKeyRuleTest {

    private val rule = HardcodedAesKeyRule(Config.empty)

    @Test
    fun `flags SecretKeySpec with byteArrayOf literals`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            fun key() = SecretKeySpec(byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10), "AES")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SecretKeySpec with literal toByteArray`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            fun key() = SecretKeySpec("my-secret-key-16!!".toByteArray(), "AES")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SecretKeySpec with encodeToByteArray`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            fun key() = SecretKeySpec("my-hardcoded-key!!".encodeToByteArray(), "AES")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores SecretKeySpec with variable key`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            fun key(keyBytes: ByteArray) = SecretKeySpec(keyBytes, "AES")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores SecretKeySpec where key comes from env`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            import java.util.Base64
            fun key(): SecretKeySpec {
                val bytes = Base64.getDecoder().decode(System.getenv("AES_KEY"))
                return SecretKeySpec(bytes, "AES")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores byteArrayOf with non-constant elements`() {
        val code = """
            import javax.crypto.spec.SecretKeySpec
            fun key(b: Byte) = SecretKeySpec(byteArrayOf(b, 0x02), "AES")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
