package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.DropwizardMissingAuthRule
import com.jasmin.security.detekt.a02.DropwizardUnencryptedJwtSecretRule
import com.jasmin.security.detekt.a02.InsecureTlsProtocolRule
import com.jasmin.security.detekt.a03.DropwizardJdbiSqlInjectionRule
import com.jasmin.security.detekt.a03.DropwizardMissingBeanValidationRule
import com.jasmin.security.detekt.a03.DropwizardSelfValidatingELRule
import com.jasmin.security.detekt.a03.DropwizardXssResponseRule
import com.jasmin.security.detekt.a05.DropwizardAdminConnectorExposedRule
import com.jasmin.security.detekt.a05.DropwizardInsecureMultipartRule
import com.jasmin.security.detekt.a05.InsecureCookieRule
import com.jasmin.security.detekt.a07.DropwizardDatabasePasswordRule
import com.jasmin.security.detekt.a07.DropwizardHardcodedTokenRule
import com.jasmin.security.detekt.a08.DropwizardJacksonPolymorphismRule
import com.jasmin.security.detekt.a09.DropwizardSensitiveDataLoggingRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class DropwizardRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-dropwizard"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            DropwizardMissingAuthRule(config),
            // A02 Cryptographic Failures
            InsecureTlsProtocolRule(config),
            DropwizardUnencryptedJwtSecretRule(config),
            // A03 Injection
            DropwizardSelfValidatingELRule(config),
            DropwizardJdbiSqlInjectionRule(config),
            DropwizardMissingBeanValidationRule(config),
            DropwizardXssResponseRule(config),
            // A05 Security Misconfiguration
            InsecureCookieRule(config),
            DropwizardAdminConnectorExposedRule(config),
            DropwizardInsecureMultipartRule(config),
            // A07 Identification and Authentication Failures
            DropwizardHardcodedTokenRule(config),
            DropwizardDatabasePasswordRule(config),
            // A08 Software and Data Integrity Failures
            DropwizardJacksonPolymorphismRule(config),
            // A09 Security Logging and Monitoring Failures
            DropwizardSensitiveDataLoggingRule(config),
        )
    )
}
