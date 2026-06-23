package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JaxrsOpenRedirectRuleTest {

    private val rule = JaxrsOpenRedirectRule(Config.empty)

    @Test
    fun `flags seeOther with dynamic URI variable`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun go(url: String) = Response.seeOther(URI(url)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags temporaryRedirect with dynamic URI`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun go(url: String) = Response.temporaryRedirect(URI(url)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags seeOther with URI-create of variable`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun go(url: String) = Response.seeOther(URI.create(url)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags HttpResponse seeOther (Micronaut style)`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun go(url: String) = HttpResponse.seeOther<Any>(URI(url))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags seeOther with interpolated string`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun go(host: String) = Response.seeOther(URI("https://${'$'}host/path")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags seeOther with URL-create of variable`() {
        val code = """
            import java.net.URL
            class Ctrl {
                fun go(url: String) = Response.seeOther(URL.create(url)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores seeOther with URI-create of literal path`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun dashboard() = Response.seeOther(URI.create("/dashboard")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores seeOther with literal URI path`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun dashboard() = Response.seeOther(URI("/dashboard")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores seeOther with hardcoded full URL`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun go() = Response.seeOther(URI("https://app.example.com/home")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores other Response methods`() {
        val code = """
            import java.net.URI
            class Ctrl {
                fun ok() = Response.ok(URI("/data")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
