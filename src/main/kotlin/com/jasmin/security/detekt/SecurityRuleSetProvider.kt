package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class SecurityRuleSetProvider : RuleSetProvider {

    override val ruleSetId: String = "security-custom"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            HardcodedCredentialsRule(config.subConfig("HardcodedCredentials")),
            SqlInjectionRule(config.subConfig("SqlInjection")),
            InsecureRandomRule(config.subConfig("InsecureRandom")),
        )
    )
}
