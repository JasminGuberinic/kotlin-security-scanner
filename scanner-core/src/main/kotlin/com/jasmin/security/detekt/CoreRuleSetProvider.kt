package com.jasmin.security.detekt

import com.jasmin.security.detekt.a02.WeakCipherModeRule
import com.jasmin.security.detekt.a03.PathTraversalRule
import com.jasmin.security.detekt.a03.SqlInjectionRule
import com.jasmin.security.detekt.a07.HardcodedCredentialsRule
import com.jasmin.security.detekt.a07.InsecureRandomRule
import com.jasmin.security.detekt.a09.SensitiveDataLoggingRule
import com.jasmin.security.detekt.a10.SsrfRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Framework-agnostic security rules.
 * Safe to add to any Kotlin project regardless of framework.
 *
 * To add a rule here: implement it in the matching a0X/ package,
 * then add it to the list below and to config/detekt/detekt.yml.
 * See .claude/commands/add-security-rule.md for the full guide.
 */
class CoreRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-core"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A02 Cryptographic Failures
            WeakCipherModeRule(config.subConfig("WeakCipherMode")),
            // A03 Injection
            SqlInjectionRule(config.subConfig("SqlInjection")),
            PathTraversalRule(config.subConfig("PathTraversal")),
            // A07 Authentication Failures
            HardcodedCredentialsRule(config.subConfig("HardcodedCredentials")),
            InsecureRandomRule(config.subConfig("InsecureRandom")),
            // A09 Logging Failures
            SensitiveDataLoggingRule(config.subConfig("SensitiveDataLogging")),
            // A10 Server-Side Request Forgery
            SsrfRule(config.subConfig("Ssrf")),
        )
    )
}
