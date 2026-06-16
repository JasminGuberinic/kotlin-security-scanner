package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.DropwizardMissingAuthRule
import com.jasmin.security.detekt.a01.DropwizardOpenRedirectRule
import com.jasmin.security.detekt.a02.DropwizardUnencryptedJwtSecretRule
import com.jasmin.security.detekt.a02.InsecureTlsProtocolRule
import com.jasmin.security.detekt.a03.DropwizardSelfValidatingELRule
import com.jasmin.security.detekt.a05.InsecureCookieRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Dropwizard / JAX-RS specific security rules.
 * Catches missing @RolesAllowed on JAX-RS resources and deprecated TLS configs.
 *
 * To add a rule: implement it in the a0X/ package and list it here.
 * See .claude/commands/add-security-rule.md for the full guide.
 */
class DropwizardRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-dropwizard"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            DropwizardMissingAuthRule(config.subConfig("DropwizardMissingAuth")),
            DropwizardOpenRedirectRule(config.subConfig("DropwizardOpenRedirect")),
            // A02 Cryptographic Failures
            InsecureTlsProtocolRule(config.subConfig("InsecureTlsProtocol")),
            DropwizardUnencryptedJwtSecretRule(config.subConfig("DropwizardUnencryptedJwtSecret")),
            // A03 Injection
            DropwizardSelfValidatingELRule(config.subConfig("DropwizardSelfValidatingEL")),
            // A05 Security Misconfiguration
            InsecureCookieRule(config.subConfig("InsecureCookie")),
        )
    )
}
