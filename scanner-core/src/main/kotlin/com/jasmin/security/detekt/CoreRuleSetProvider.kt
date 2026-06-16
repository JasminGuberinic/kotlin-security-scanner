package com.jasmin.security.detekt

import com.jasmin.security.detekt.a02.HardcodedIvRule
import com.jasmin.security.detekt.a02.TrustAllCertsRule
import com.jasmin.security.detekt.a02.WeakCipherModeRule
import com.jasmin.security.detekt.a02.WeakHashAlgorithmRule
import com.jasmin.security.detekt.a03.CommandInjectionRule
import com.jasmin.security.detekt.a03.JndiInjectionRule
import com.jasmin.security.detekt.a03.LdapInjectionRule
import com.jasmin.security.detekt.a03.PathTraversalRule
import com.jasmin.security.detekt.a03.ReflectionInjectionRule
import com.jasmin.security.detekt.a03.SqlInjectionRule
import com.jasmin.security.detekt.a03.XpathInjectionRule
import com.jasmin.security.detekt.a03.XxeInjectionRule
import com.jasmin.security.detekt.a07.HardcodedCredentialsRule
import com.jasmin.security.detekt.a07.InsecureRandomRule
import com.jasmin.security.detekt.a08.InsecureDeserializationRule
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
            WeakHashAlgorithmRule(config.subConfig("WeakHashAlgorithm")),
            TrustAllCertsRule(config.subConfig("TrustAllCerts")),
            HardcodedIvRule(config.subConfig("HardcodedIv")),
            // A03 Injection
            SqlInjectionRule(config.subConfig("SqlInjection")),
            LdapInjectionRule(config.subConfig("LdapInjection")),
            JndiInjectionRule(config.subConfig("JndiInjection")),
            XpathInjectionRule(config.subConfig("XpathInjection")),
            ReflectionInjectionRule(config.subConfig("ReflectionInjection")),
            PathTraversalRule(config.subConfig("PathTraversal")),
            CommandInjectionRule(config.subConfig("CommandInjection")),
            XxeInjectionRule(config.subConfig("XxeInjection")),
            // A07 Authentication Failures
            HardcodedCredentialsRule(config.subConfig("HardcodedCredentials")),
            InsecureRandomRule(config.subConfig("InsecureRandom")),
            // A08 Software and Data Integrity
            InsecureDeserializationRule(config.subConfig("InsecureDeserialization")),
            // A09 Logging Failures
            SensitiveDataLoggingRule(config.subConfig("SensitiveDataLogging")),
            // A10 Server-Side Request Forgery
            SsrfRule(config.subConfig("Ssrf")),
        )
    )
}
