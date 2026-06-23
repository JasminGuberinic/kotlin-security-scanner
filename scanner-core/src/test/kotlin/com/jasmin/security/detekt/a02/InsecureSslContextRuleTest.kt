package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureSslContextRuleTest {

    private val rule = InsecureSslContextRule(Config.empty)

    @Test
    fun `flags SSLContext getInstance SSLv3`() {
        val code = """
            import javax.net.ssl.SSLContext
            fun ctx() = SSLContext.getInstance("SSLv3")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SSLContext getInstance TLSv1_1`() {
        val code = """
            import javax.net.ssl.SSLContext
            fun ctx() = SSLContext.getInstance("TLSv1.1")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores SSLContext getInstance TLSv1_3`() {
        val code = """
            import javax.net.ssl.SSLContext
            fun ctx() = SSLContext.getInstance("TLSv1.3")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores MessageDigest getInstance with a weak-looking name`() {
        val code = """
            import java.security.MessageDigest
            fun digest() = MessageDigest.getInstance("MD5")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
