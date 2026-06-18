package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.DropwizardMissingAuthRule
import com.jasmin.security.detekt.a01.DropwizardOpenRedirectRule
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
            DropwizardMissingAuthRule(config.subConfig("DropwizardMissingAuth")),
            DropwizardOpenRedirectRule(config.subConfig("DropwizardOpenRedirect")),
            // A02 Cryptographic Failures
            InsecureTlsProtocolRule(config.subConfig("InsecureTlsProtocol")),
            DropwizardUnencryptedJwtSecretRule(config.subConfig("DropwizardUnencryptedJwtSecret")),
            // A03 Injection
            DropwizardSelfValidatingELRule(config.subConfig("DropwizardSelfValidatingEL")),
            DropwizardJdbiSqlInjectionRule(config.subConfig("DropwizardJdbiSqlInjection")),
            DropwizardMissingBeanValidationRule(config.subConfig("DropwizardMissingBeanValidation")),
            DropwizardXssResponseRule(config.subConfig("DropwizardXssResponse")),
            // A05 Security Misconfiguration
            InsecureCookieRule(config.subConfig("InsecureCookie")),
            DropwizardAdminConnectorExposedRule(config.subConfig("DropwizardAdminConnectorExposed")),
            DropwizardInsecureMultipartRule(config.subConfig("DropwizardInsecureMultipart")),
            // A07 Identification and Authentication Failures
            DropwizardHardcodedTokenRule(config.subConfig("DropwizardHardcodedToken")),
            DropwizardDatabasePasswordRule(config.subConfig("DropwizardDatabasePassword")),
            // A08 Software and Data Integrity Failures
            DropwizardJacksonPolymorphismRule(config.subConfig("DropwizardJacksonPolymorphism")),
            // A09 Security Logging and Monitoring Failures
            DropwizardSensitiveDataLoggingRule(config.subConfig("DropwizardSensitiveDataLogging")),
        )
    )
}
