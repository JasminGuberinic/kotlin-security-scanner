package com.jasmin.security.detekt

import com.jasmin.security.detekt.a02.HardcodedIvRule
import com.jasmin.security.detekt.a02.InsecurePasswordStorageRule
import com.jasmin.security.detekt.a02.JwtNoneAlgorithmRule
import com.jasmin.security.detekt.a02.JwtWeakSecretRule
import com.jasmin.security.detekt.a02.TrustAllCertsRule
import com.jasmin.security.detekt.a02.UnsafeCryptoPaddingOracleRule
import com.jasmin.security.detekt.a02.WeakCipherModeRule
import com.jasmin.security.detekt.a02.WeakHashAlgorithmRule
import com.jasmin.security.detekt.a02.WeakRsaKeyRule
import com.jasmin.security.detekt.a03.CommandInjectionRule
import com.jasmin.security.detekt.a03.GroovyScriptInjectionRule
import com.jasmin.security.detekt.a03.JndiInjectionRule
import com.jasmin.security.detekt.a03.LdapInjectionRule
import com.jasmin.security.detekt.a03.PathTraversalRule
import com.jasmin.security.detekt.a03.ReflectionInjectionRule
import com.jasmin.security.detekt.a03.SqlInjectionRule
import com.jasmin.security.detekt.a03.XpathInjectionRule
import com.jasmin.security.detekt.a03.XxeInjectionRule
import com.jasmin.security.detekt.a06.RegexDenialOfServiceRule
import com.jasmin.security.detekt.a07.HardcodedAwsCredentialsRule
import com.jasmin.security.detekt.a07.HardcodedCredentialsRule
import com.jasmin.security.detekt.a07.InsecureRandomRule
import com.jasmin.security.detekt.a08.InsecureDeserializationRule
import com.jasmin.security.detekt.a08.JacksonUnsafeDeserializationRule
import com.jasmin.security.detekt.a08.KotlinxSerializationSensitiveFieldRule
import com.jasmin.security.detekt.a08.XmlMapperUnsafeRule
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

    // config is the rule-set config (security-core section). Each Rule subclass
    // receives it as ruleSetConfig and self-scopes via getRuleConfig() = ruleSetConfig.subConfig(ruleId).
    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A02 Cryptographic Failures
            WeakCipherModeRule(config),
            WeakHashAlgorithmRule(config),
            TrustAllCertsRule(config),
            HardcodedIvRule(config),
            WeakRsaKeyRule(config),
            JwtNoneAlgorithmRule(config),
            JwtWeakSecretRule(config),
            UnsafeCryptoPaddingOracleRule(config),
            InsecurePasswordStorageRule(config),
            // A03 Injection
            SqlInjectionRule(config),
            LdapInjectionRule(config),
            JndiInjectionRule(config),
            XpathInjectionRule(config),
            ReflectionInjectionRule(config),
            PathTraversalRule(config),
            CommandInjectionRule(config),
            XxeInjectionRule(config),
            GroovyScriptInjectionRule(config),
            // A06 Vulnerable Components / ReDoS
            RegexDenialOfServiceRule(config),
            // A07 Authentication Failures
            HardcodedCredentialsRule(config),
            InsecureRandomRule(config),
            HardcodedAwsCredentialsRule(config),
            // A08 Software and Data Integrity
            InsecureDeserializationRule(config),
            JacksonUnsafeDeserializationRule(config),
            XmlMapperUnsafeRule(config),
            KotlinxSerializationSensitiveFieldRule(config),
            // A09 Logging Failures
            SensitiveDataLoggingRule(config),
            // A10 Server-Side Request Forgery
            SsrfRule(config),
        )
    )
}
