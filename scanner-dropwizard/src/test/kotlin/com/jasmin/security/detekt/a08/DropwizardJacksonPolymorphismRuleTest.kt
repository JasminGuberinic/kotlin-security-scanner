package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardJacksonPolymorphismRuleTest {

    private val rule = DropwizardJacksonPolymorphismRule(Config.empty)

    @Test
    fun `flags enableDefaultTyping call`() {
        val code = """
            fun configureMapper(): ObjectMapper {
                val mapper = ObjectMapper()
                mapper.enableDefaultTyping()
                return mapper
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags enableDefaultTyping with arguments`() {
        val code = """
            fun configureMapper(): ObjectMapper {
                val mapper = ObjectMapper()
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL)
                return mapper
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores safe mapper configuration`() {
        val code = """
            fun configureMapper(): ObjectMapper {
                val mapper = ObjectMapper()
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                return mapper
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with insecure cookie code`() {
        val code = """
            val cookie = NewCookie("session", token)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
