package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class SecurityRuleSetProvider : RuleSetProvider {

    override val ruleSetId: String = "security-custom"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A02 Cryptographic Failures
            WeakCipherModeRule(config.subConfig("WeakCipherMode")),
            // A03 Injection
            SqlInjectionRule(config.subConfig("SqlInjection")),
            PathTraversalRule(config.subConfig("PathTraversal")),
            // A05 Security Misconfiguration
            SpringCsrfDisabledRule(config.subConfig("SpringCsrfDisabled")),
            // A07 Authentication Failures
            HardcodedCredentialsRule(config.subConfig("HardcodedCredentials")),
            InsecureRandomRule(config.subConfig("InsecureRandom")),
            // A09 Logging Failures
            SensitiveDataLoggingRule(config.subConfig("SensitiveDataLogging")),
        )
    )
}
