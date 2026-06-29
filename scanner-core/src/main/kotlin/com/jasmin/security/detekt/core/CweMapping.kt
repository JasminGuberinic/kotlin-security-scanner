package com.jasmin.security.detekt.core

/**
 * Authoritative mapping from rule ID to CWE (Common Weakness Enumeration) identifiers.
 *
 * Referenced by SecurityRule.reportAt to append [CWE-XX] to every finding message —
 * so CWE IDs appear in console output, SARIF exports, and IDE annotations without
 * modifying individual rule files.
 *
 * Reference: https://cwe.mitre.org/
 */
object CweMapping {

    // ── Core rules ────────────────────────────────────────────────────────────

    private val MAP: Map<String, String> = mapOf(
        // A01 Broken Access Control
        "JaxrsOpenRedirect" to "CWE-601",
        "PredictableTempFile" to "CWE-377",
        // A02 Cryptographic Failures
        "HardcodedAesKey" to "CWE-321",
        "InsecureSslContext" to "CWE-326",
        "HardcodedPrivateKey" to "CWE-321",
        "InsecureRandomSeed" to "CWE-335",
        "TrustAllHostnames" to "CWE-297",
        "WeakCipherMode" to "CWE-327",
        "WeakHashAlgorithm" to "CWE-327",
        "TrustAllCerts" to "CWE-295",
        "HardcodedIv" to "CWE-330",
        "WeakRsaKey" to "CWE-326",
        "JwtNoneAlgorithm" to "CWE-347",
        "JwtWeakSecret" to "CWE-798",
        "UnsafeCryptoPaddingOracle" to "CWE-327",
        "InsecurePasswordStorage" to "CWE-916",
        // A03 Injection
        "SqlInjection" to "CWE-89",
        "LdapInjection" to "CWE-90",
        "JndiInjection" to "CWE-74",
        "XpathInjection" to "CWE-643",
        "ReflectionInjection" to "CWE-470",
        "PathTraversal" to "CWE-22",
        "CommandInjection" to "CWE-78",
        "XxeInjection" to "CWE-611",
        "GroovyScriptInjection" to "CWE-94",
        "ZipSlip" to "CWE-22",
        "RegexDenialOfService" to "CWE-1333",
        "RegexInjection" to "CWE-1333",
        // A07 Identification and Authentication Failures
        "HardcodedCredentials" to "CWE-798",
        "InsecureRandom" to "CWE-330",
        "HardcodedAwsCredentials" to "CWE-798",
        "GoogleApiKey" to "CWE-798",
        "SlackToken" to "CWE-798",
        "GitHubToken" to "CWE-798",
        "StripeSecretKey" to "CWE-798",
        "HardcodedJwtToken" to "CWE-798",
        "HardcodedJdbcCredentials" to "CWE-798",
        // A08 Software and Data Integrity
        "InsecureDeserialization" to "CWE-502",
        "JacksonUnsafeDeserialization" to "CWE-502",
        "XmlMapperUnsafe" to "CWE-502",
        "KotlinxSerializationSensitiveField" to "CWE-312",
        // A05 Security Misconfiguration
        "CorsWildcardOrigins" to "CWE-942",
        "InsecureFilePermissions" to "CWE-732",
        // A09 Logging
        "SensitiveDataLogging" to "CWE-532",
        "LogForging" to "CWE-117",
        // A10 SSRF
        "Ssrf" to "CWE-918",

        // ── Spring Boot rules ─────────────────────────────────────────────────

        // A01 Broken Access Control
        "MissingAuthorization" to "CWE-285",
        "DisabledHttpSecurity" to "CWE-284",
        "OpenRedirect" to "CWE-601",
        "CsrfTokenLeak" to "CWE-352",
        "CoroutineSecurityContextLoss" to "CWE-272",
        // A02 Cryptographic Failures
        "InsecurePasswordEncoder" to "CWE-916",
        "WeakBcryptRounds" to "CWE-916",
        "JwtExpirationMissing" to "CWE-613",
        "MissingHttpsRedirect" to "CWE-319",
        "InsecureRedisConnection" to "CWE-319",
        "InsecureSmtpConfig" to "CWE-319",
        // A03 Injection
        "SpelInjection" to "CWE-94",
        "ResponseSplitting" to "CWE-113",
        "ELInjection" to "CWE-94",
        "SpringDataMongoInjection" to "CWE-943",
        "ThymeleafSSTI" to "CWE-94",
        // A04 Insecure Design
        "MassAssignment" to "CWE-915",
        // A05 Security Misconfiguration
        "SpringCsrfDisabled" to "CWE-352",
        "PermissiveCors" to "CWE-942",
        "InsecureActuatorExposure" to "CWE-200",
        "SecurityHeadersMissing" to "CWE-693",
        "ExceptionDetailsExposed" to "CWE-209",
        "HttpMethodOverride" to "CWE-352",
        // A10 SSRF
        "WebClientSSRF" to "CWE-918",
        // A01 (new)
        "AsyncSecurityContextLoss" to "CWE-272",
        "FeignClientInsecureUrl" to "CWE-319",
        // A02 (new)
        "JwtSecretInProperties" to "CWE-798",
        // A03 (new)
        "EntityManagerJpqlInjection" to "CWE-89",
        // A05 (new)
        "KafkaTrustedPackagesWildcard" to "CWE-502",
        "KafkaInsecureProtocol" to "CWE-319",
        "SpringSecurityDebugEnabled" to "CWE-489",
        "H2ConsoleEnabled" to "CWE-489",
        // A07 (new)
        "InsecureRememberMe" to "CWE-798",
        // A09 (new)
        "ShowSqlEnabled" to "CWE-532",
        // A10 (new)
        "RestTemplateSsrf" to "CWE-918",
        // Spring Boot batch 2
        "OAuth2ClientSecretInProperties" to "CWE-798",
        "HardcodedDatasourcePassword" to "CWE-798",
        "SpringActuatorShutdownEnabled" to "CWE-489",
        "CloudConfigInsecureUri" to "CWE-319",
        "SpringDataSortInjection" to "CWE-89",
        "UnvalidatedForward" to "CWE-601",
        "SpringCacheableSensitive" to "CWE-312",
        "CrossOriginCredentialsWildcard" to "CWE-942",
        "PermitAllAdminPath" to "CWE-285",
        "SecurityLoggingVerbose" to "CWE-532",
        // Spring Boot batch 3
        "SpringBootNoOpPasswordEncoder" to "CWE-312",
        "SpringBootHardcodedValueDefault" to "CWE-798",
        "SpringBootCookieNotHttpOnly" to "CWE-1004",
        "SpringBootInsecureFileUpload" to "CWE-22",
        "SpringBootRequestBodyAnyType" to "CWE-502",
        "SpringBootExceptionBodyLeak" to "CWE-209",
        "SpringFrameOptionsDisabled" to "CWE-1021",
        "SpringContentTypeOptionsDisabled" to "CWE-693",
        "SpringSessionFixationNone" to "CWE-384",
        "SpringCsrfIgnoringMatchers" to "CWE-352",
        // WebFlux (reactive)
        "ReactiveSecurityContextHolder" to "CWE-863",
        "ReactivePermitAllExchange" to "CWE-285",
        "WebFluxBlockingCall" to "CWE-400",

        // ── Quarkus rules ─────────────────────────────────────────────────────

        // A01 Broken Access Control
        "QuarkusSystemExit" to "CWE-733",
        "QuarkusMissingAuth" to "CWE-285",
        "QuarkusPermitAllSensitive" to "CWE-285",
        "QuarkusJsonBeforeAuth" to "CWE-285",
        // A02 Cryptographic Failures
        "QuarkusSmallryeJwtInsecure" to "CWE-347",
        // A03 Injection
        "PanacheRawQuery" to "CWE-89",
        "QuarkusMissingBeanValidation" to "CWE-20",
        // A05 Security Misconfiguration
        "QuarkusBuildTimeSecretLeak" to "CWE-798",
        "QuarkusUnsafeHeader" to "CWE-113",
        "QuarkusCorsPermissiveConfig" to "CWE-942",
        "QuarkusDevServicesInProd" to "CWE-489",
        // A07 Identification and Authentication Failures
        "QuarkusHardcodedConfigSecret" to "CWE-798",
        "QuarkusOidcInsecureConfig" to "CWE-295",
        "QuarkusHardcodedDatasourcePassword" to "CWE-798",
        // A08 Software and Data Integrity
        "QuarkusReflectionUnsafe" to "CWE-502",
        // Quarkus Batch 2
        "QuarkusRestClientInsecureUrl" to "CWE-319",
        "QuarkusGraphQLNoAuth" to "CWE-285",
        "QuarkusReactiveRouteNoAuth" to "CWE-285",
        "QuarkusRedisInsecure" to "CWE-319",
        "QuarkusMongoInsecure" to "CWE-319",
        "QuarkusOidcAudienceMissing" to "CWE-345",
        "QuarkusGrpcInsecure" to "CWE-319",
        "QuarkusNativeQueryInjection" to "CWE-89",
        "QuarkusPathParamInjection" to "CWE-89",
        "QuarkusMultipartInsecure" to "CWE-400",
        "QuarkusSmallRyeHealthInsecure" to "CWE-489",
        "QuarkusSwaggerUiInProd" to "CWE-489",
        "QuarkusConfigPasswordLeak" to "CWE-798",
        // Quarkus batch 3
        "QuarkusFormCsrfMissing" to "CWE-352",
        "QuarkusUnsafeSecurityContext" to "CWE-285",
        "QuarkusSensitiveQueryParam" to "CWE-598",
        "QuarkusMassAssignment" to "CWE-915",
        "QuarkusInsecureCookie" to "CWE-614",
        "QuarkusInsecureFileUpload" to "CWE-22",
        "QuarkusHardcodedConfigPropertyDefault" to "CWE-798",
        "QuarkusJsonbUnsafeDeserialization" to "CWE-502",
        "QuarkusExceptionMessageLeak" to "CWE-209",
        "QuarkusPasswordInLog" to "CWE-532",
        "QuarkusCacheResultSensitive" to "CWE-285",

        // ── Dropwizard rules ──────────────────────────────────────────────────

        // A01 Broken Access Control
        "DropwizardMissingAuth" to "CWE-285",
        // A02 Cryptographic Failures
        "InsecureTlsProtocol" to "CWE-326",
        "DropwizardUnencryptedJwtSecret" to "CWE-798",
        // A03 Injection
        "DropwizardSelfValidatingEL" to "CWE-94",
        "DropwizardJdbiSqlInjection" to "CWE-89",
        "DropwizardMissingBeanValidation" to "CWE-20",
        "DropwizardXssResponse" to "CWE-79",
        // A05 Security Misconfiguration
        "InsecureCookie" to "CWE-614",
        "DropwizardAdminConnectorExposed" to "CWE-284",
        "DropwizardInsecureMultipart" to "CWE-400",
        // A07 Identification and Authentication Failures
        "DropwizardHardcodedToken" to "CWE-798",
        "DropwizardDatabasePassword" to "CWE-798",
        // A08 Software and Data Integrity Failures
        "DropwizardJacksonPolymorphism" to "CWE-502",
        // A09 Security Logging and Monitoring Failures
        "DropwizardSensitiveDataLogging" to "CWE-532",

        // ── Ktor rules ────────────────────────────────────────────────────────

        // A01 Broken Access Control
        "KtorMissingAuth" to "CWE-285",
        "KtorInsecureRedirect" to "CWE-601",
        "KtorCsrfMissing" to "CWE-352",
        // A02 Cryptographic Failures
        "KtorBasicAuthInsecure" to "CWE-319",
        "KtorWeakJwtSecret" to "CWE-798",
        // A03 Injection
        "KtorXssResponse" to "CWE-79",
        "KtorExposedOrmInjection" to "CWE-89",
        "KtorSensitiveRouteParam" to "CWE-200",
        // A05 Security Misconfiguration
        "KtorInsecureCookieSession" to "CWE-565",
        "KtorPermissiveCors" to "CWE-942",
        "KtorClearTextCookie" to "CWE-614",
        "KtorSecurityHeadersMissing" to "CWE-693",
        "KtorSslRedirectMissing" to "CWE-319",
        "KtorRateLimitingMissing" to "CWE-307",
        "KtorSessionCookieDomainMissing" to "CWE-565",
        // A07 Identification and Authentication Failures
        "KtorHardcodedSecretKey" to "CWE-798",
        "KtorHardcodedPasswordComparison" to "CWE-798",
        "KtorHardcodedDatabasePassword" to "CWE-798",
        // A09 Security Logging and Monitoring Failures
        "KtorLoggingCredentials" to "CWE-532",
        // Faza 2 — Exposed ORM
        "KtorExposedDeleteAll" to "CWE-285",
        "KtorExposedConnectionNotSecure" to "CWE-319",
        "KtorExposedRawSqlConcat" to "CWE-89",
        "KtorExposedSchemaAutoCreate" to "CWE-284",
        // Faza 3 — Ktor extensions
        "KtorWebSocketNoAuth" to "CWE-285",
        "KtorFileUploadTraversal" to "CWE-22",
        "KtorUnvalidatedQueryParam" to "CWE-20",
        "KtorRawCallReceive" to "CWE-20",
        "KtorForwardedHeaderTrust" to "CWE-346",
        "KtorMultipartInsecureUpload" to "CWE-400",
        "KtorInsecureContentNegotiation" to "CWE-502",
        "KtorStatusPageLeakDetails" to "CWE-209",
        "KtorRespondFileTraversal" to "CWE-22",
        "KtorDevelopmentMode" to "CWE-489",
        "KtorCorsAnyHeader" to "CWE-942",

        // ── Micronaut rules ───────────────────────────────────────────────────

        "MicronautMissingSecured" to "CWE-285",
        "MicronautWebSocketNoAuth" to "CWE-285",
        "MicronautCacheableSensitive" to "CWE-285",
        "MicronautRetryOnAuth" to "CWE-307",
        "MicronautGrpcInsecure" to "CWE-319",
        "MicronautManagementEndpointInsecure" to "CWE-284",
        "MicronautInsecureHttpClient" to "CWE-319",
        "MicronautSensitiveQueryParam" to "CWE-598",
        "MicronautBodyAnyType" to "CWE-20",
        "MicronautHardcodedSecret" to "CWE-798",
        "MicronautExceptionMessageLeak" to "CWE-209",
        "MicronautAnonymousAccess" to "CWE-285",
        "MicronautInsecureCookie" to "CWE-614",

        // ── Vert.x rules ──────────────────────────────────────────────────────

        "VertxTrustAllCerts" to "CWE-295",
        "VertxCorsWildcard" to "CWE-942",
        "VertxBodyHandlerNoLimit" to "CWE-400",
        "VertxEventBusBridgeOpen" to "CWE-862",
        "VertxInsecureCookie" to "CWE-614",
    )

    /** Returns the CWE tag string for a given rule ID, e.g. "CWE-89". Null if not mapped. */
    fun forRule(ruleId: String): String? = MAP[ruleId]
}
