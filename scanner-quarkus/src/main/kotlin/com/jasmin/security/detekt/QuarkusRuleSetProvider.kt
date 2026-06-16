package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.QuarkusMissingAuthRule
import com.jasmin.security.detekt.a01.QuarkusPermitAllSensitiveRule
import com.jasmin.security.detekt.a03.PanacheRawQueryRule
import com.jasmin.security.detekt.a05.QuarkusBuildTimeSecretLeakRule
import com.jasmin.security.detekt.a05.QuarkusUnsafeHeaderRule
import com.jasmin.security.detekt.a07.QuarkusHardcodedConfigSecretRule
import com.jasmin.security.detekt.a07.QuarkusOidcInsecureConfigRule
import com.jasmin.security.detekt.a08.QuarkusReflectionUnsafeRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Quarkus / MicroProfile specific security rules.
 * Catches missing access control on JAX-RS resources and hardcoded
 * secrets in @ConfigProperty default values.
 *
 * To add a rule: implement it in the a0X/ package and list it here.
 * See .claude/commands/add-security-rule.md for the full guide.
 */
class QuarkusRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-quarkus"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            QuarkusMissingAuthRule(config.subConfig("QuarkusMissingAuth")),
            QuarkusPermitAllSensitiveRule(config.subConfig("QuarkusPermitAllSensitive")),
            // A03 Injection
            PanacheRawQueryRule(config.subConfig("PanacheRawQuery")),
            // A05 Security Misconfiguration
            QuarkusUnsafeHeaderRule(config.subConfig("QuarkusUnsafeHeader")),
            QuarkusBuildTimeSecretLeakRule(config.subConfig("QuarkusBuildTimeSecretLeak")),
            // A07 Identification and Authentication Failures
            QuarkusHardcodedConfigSecretRule(config.subConfig("QuarkusHardcodedConfigSecret")),
            QuarkusOidcInsecureConfigRule(config.subConfig("QuarkusOidcInsecureConfig")),
            // A08 Software and Data Integrity
            QuarkusReflectionUnsafeRule(config.subConfig("QuarkusReflectionUnsafe")),
        )
    )
}
