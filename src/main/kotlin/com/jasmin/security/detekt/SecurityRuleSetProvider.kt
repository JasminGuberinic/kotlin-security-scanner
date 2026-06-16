package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.MissingAuthorizationRule
import com.jasmin.security.detekt.a02.WeakCipherModeRule
import com.jasmin.security.detekt.a03.PathTraversalRule
import com.jasmin.security.detekt.a03.SqlInjectionRule
import com.jasmin.security.detekt.a05.PermissiveCorsRule
import com.jasmin.security.detekt.a05.SpringCsrfDisabledRule
import com.jasmin.security.detekt.a07.HardcodedCredentialsRule
import com.jasmin.security.detekt.a07.InsecureRandomRule
import com.jasmin.security.detekt.a09.SensitiveDataLoggingRule
import com.jasmin.security.detekt.a10.SsrfRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Registers all custom security rules with the Detekt engine via SPI.
 *
 * Rules are grouped by OWASP Top 10 (2021) category.
 * To add a new rule: implement it in the matching a0X package, then add
 * it to the list below and to config/detekt/detekt.yml.
 *
 * See .claude/commands/add-security-rule.md for the full contribution guide.
 */
class SecurityRuleSetProvider : RuleSetProvider {

    override val ruleSetId: String = "security-custom"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            MissingAuthorizationRule(config.subConfig("MissingAuthorization")),
            // A02 Cryptographic Failures
            WeakCipherModeRule(config.subConfig("WeakCipherMode")),
            // A03 Injection
            SqlInjectionRule(config.subConfig("SqlInjection")),
            PathTraversalRule(config.subConfig("PathTraversal")),
            // A05 Security Misconfiguration
            SpringCsrfDisabledRule(config.subConfig("SpringCsrfDisabled")),
            PermissiveCorsRule(config.subConfig("PermissiveCors")),
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
