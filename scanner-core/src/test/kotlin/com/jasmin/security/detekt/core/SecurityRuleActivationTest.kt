package com.jasmin.security.detekt.core

import com.jasmin.security.detekt.a02.WeakHashAlgorithmRule
import io.gitlab.arturbosch.detekt.test.TestConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * Guards the security-critical default: every SecurityRule must be ACTIVE out of the box.
 *
 * Detekt's stock default for an unconfigured rule is `active = false`. If that leaked
 * through, a consumer who just adds the plugin (buildUponDefaultConfig = true, no per-rule
 * config) would get zero findings — the plugin would silently protect nothing. The
 * `SecurityRule.active` override flips the default to true; these tests lock that in and
 * confirm an explicit `active: false` still disables a rule.
 *
 * Uses a non-empty TestConfig (NOT Config.empty) so it reflects a real consumer config
 * rather than the EmptyConfig special-case that always reports active = true.
 */
class SecurityRuleActivationTest {

    @Test
    fun `a rule is active by default when the config omits the active flag`() {
        val rule = WeakHashAlgorithmRule(TestConfig("unrelatedKey" to "value"))
        assertThat(rule.active).isTrue()
    }

    @Test
    fun `a rule can still be disabled with active false`() {
        val rule = WeakHashAlgorithmRule(TestConfig("active" to "false"))
        assertThat(rule.active).isFalse()
    }
}
