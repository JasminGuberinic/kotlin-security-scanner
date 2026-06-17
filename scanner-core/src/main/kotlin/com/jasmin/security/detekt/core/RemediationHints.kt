package com.jasmin.security.detekt.core

/**
 * Authoritative mapping from rule ID to a short, actionable fix hint.
 *
 * Referenced by SecurityRule.reportAt to append "Fix: ..." to every finding —
 * so developers see the compliant alternative immediately in their IDE or CI log,
 * without having to search docs.
 *
 * Keep hints under 120 chars; show compliant code, not prose.
 */
object RemediationHints {

    private val MAP: Map<String, String> = mapOf(

        // ── Core — A02 Cryptographic Failures ────────────────────────────────

        "WeakCipherMode" to
            """Cipher.getInstance("AES/GCM/NoPadding") // authenticated encryption, no padding oracle""",

        "WeakHashAlgorithm" to
            """MessageDigest.getInstance("SHA-256") // or BCrypt/Argon2 for passwords""",

        "TrustAllCerts" to
            "Remove the empty checkServerTrusted override; load a proper CA bundle via TrustManagerFactory",

        "HardcodedIv" to
            "val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }",

        "WeakRsaKey" to
            "kpg.initialize(2048) // NIST SP 800-57 minimum; prefer 4096 for long-lived keys",

        "JwtNoneAlgorithm" to
            """Jwts.builder().signWith(key, SignatureAlgorithm.HS256).compact()""",

        "JwtWeakSecret" to
            """val secret = System.getenv("JWT_SECRET") ?: error("JWT_SECRET not set")""",

        "UnsafeCryptoPaddingOracle" to
            """Cipher.getInstance("AES/GCM/NoPadding") // GCM provides authenticated encryption""",

        "InsecurePasswordStorage" to
            "BCryptPasswordEncoder(12).encode(rawPassword)",

        // ── Core — A03 Injection ─────────────────────────────────────────────

        "SqlInjection" to
            """jdbcTemplate.query("SELECT … WHERE id = ?", id) // use parameterised query""",

        "LdapInjection" to
            "LdapUtils.escapeLdapSearchFilter(input) before passing to search()",

        "JndiInjection" to
            "Avoid dynamic JNDI lookups; bind resources at startup with static names only",

        "XpathInjection" to
            "Use XPathVariableResolver to bind values instead of string concatenation",

        "ReflectionInjection" to
            "Validate className against a hardcoded allowlist before Class.forName(className)",

        "PathTraversal" to
            "Paths.get(baseDir).resolve(input).normalize().also { check(it.startsWith(baseDir)) }",

        "CommandInjection" to
            "ProcessBuilder(listOf(\"cmd\", \"--flag\", sanitizedArg)) // never concatenate into shell string",

        "XxeInjection" to
            "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",

        "GroovyScriptInjection" to
            "Never execute user-supplied scripts; implement a constrained DSL with an allowlist",

        "RegexDenialOfService" to
            "Rewrite to avoid nested quantifiers; add .find(input.take(1000)) length guard",

        // ── Core — A07 Identification and Authentication Failures ────────────

        "HardcodedCredentials" to
            """val secret = System.getenv("MY_SECRET") ?: error("MY_SECRET not set")""",

        "InsecureRandom" to
            "val rng = SecureRandom() // java.security.SecureRandom",

        "HardcodedAwsCredentials" to
            "Use IAM roles or EnvironmentVariableCredentialsProvider — never hardcode AKIA keys",

        // ── Core — A08 Software and Data Integrity ────────────────────────────

        "InsecureDeserialization" to
            "ValidatingObjectInputStream(stream).accept(TrustedClass::class.java)",

        "JacksonUnsafeDeserialization" to
            "Remove enableDefaultTyping(); add @JsonTypeInfo only on classes you own",

        "XmlMapperUnsafe" to
            "val mapper = XmlMapper().disable(MapperFeature.DEFAULT_VIEW_INCLUSION) and disable DTD",

        "KotlinxSerializationSensitiveField" to
            "@Transient val password: String = \"\" // excluded from serialised output",

        // ── Core — A09 Logging Failures ──────────────────────────────────────

        "SensitiveDataLogging" to
            """log.debug("Authenticated userId={}", user.id) // log ID, not the secret value""",

        // ── Core — A10 SSRF ──────────────────────────────────────────────────

        "Ssrf" to
            "Validate URL host against a hardcoded allowlist before opening any URL/URI connection",

        // ── Spring Boot — A01 Broken Access Control ──────────────────────────

        "MissingAuthorization" to
            """@PreAuthorize("hasRole('USER')") on every @GetMapping/@PostMapping handler""",

        "DisabledHttpSecurity" to
            "Remove .authorizeRequests().anyRequest().permitAll() — use role-scoped matchers",

        "OpenRedirect" to
            """require(URI(redirectUrl).host == "your-app.com") { "Untrusted redirect host" }""",

        "CsrfTokenLeak" to
            "Never include the CSRF token in API response bodies; read it from the cookie only",

        "CoroutineSecurityContextLoss" to
            "withContext(SecurityCoroutineContext()) { ... } to propagate the security context",

        // ── Spring Boot — A02 Cryptographic Failures ─────────────────────────

        "InsecurePasswordEncoder" to
            "@Bean fun encoder(): PasswordEncoder = BCryptPasswordEncoder(12)",

        "WeakBcryptRounds" to
            "BCryptPasswordEncoder(12) // NIST SP 800-63B; each +1 doubles compute cost",

        "JwtExpirationMissing" to
            ".setExpiration(Date.from(Instant.now().plusSeconds(3600)))",

        "MissingHttpsRedirect" to
            "http.requiresChannel().anyRequest().requiresSecure()",

        "InsecureRedisConnection" to
            "LettuceConnectionFactory with clientConfig.useSsl(true).disablePeerVerification(false)",

        "InsecureSmtpConfig" to
            "mail.smtp.ssl.enable=true, mail.smtp.ssl.protocols=TLSv1.2 in application.properties",

        // ── Spring Boot — A03 Injection ───────────────────────────────────────

        "SpelInjection" to
            "SimpleEvaluationContext.forReadOnlyDataBinding().build() — restricts SpEL operators",

        "ResponseSplitting" to
            """header.value.replace("\r\n", "").replace("\n", "") before setHeader()""",

        "ELInjection" to
            "Use static message template strings — never pass user input to createValueExpression()",

        "SpringDataMongoInjection" to
            """Query.query(Criteria.where("field").is(userInput)) — use typed Criteria, not raw JSON""",

        "ThymeleafSSTI" to
            "th:text or th:utext in templates — never pass user-controlled strings to process()",

        // ── Spring Boot — A04 Insecure Design ────────────────────────────────

        "MassAssignment" to
            "Use a dedicated DTO with explicit fields — never bind HttpServletRequest directly to @Entity",

        // ── Spring Boot — A05 Security Misconfiguration ───────────────────────

        "SpringCsrfDisabled" to
            "Remove .csrf().disable() — Spring Security enables CSRF protection by default",

        "PermissiveCors" to
            """.allowedOrigins("https://your-app.com") — remove the wildcard origin""",

        "InsecureActuatorExposure" to
            "management.endpoints.web.exposure.include=health,info only in production",

        "SecurityHeadersMissing" to
            """http.headers().contentSecurityPolicy("default-src 'self'").and().frameOptions().deny()""",

        "ExceptionDetailsExposed" to
            "Return a generic error message; log the full exception server-side only",

        "HttpMethodOverride" to
            "Remove the HiddenHttpMethodFilter @Bean — it opens CSRF bypass vectors",

        // ── Spring Boot — A10 SSRF ────────────────────────────────────────────

        "WebClientSSRF" to
            "Validate URL host against an allowlist before WebClient.create(url).get().retrieve()",

        // ── Quarkus — A01 Broken Access Control ──────────────────────────────

        "QuarkusMissingAuth" to
            """@RolesAllowed("user") on the @GET/@POST method (or the resource class)""",

        "QuarkusPermitAllSensitive" to
            """Replace @PermitAll with @RolesAllowed("admin") on write/delete endpoints""",

        "QuarkusJsonBeforeAuth" to
            """Move @RolesAllowed to class level — annotate the @Path class, not individual methods""",

        "QuarkusOpenRedirect" to
            "Validate redirect URI against a trusted-domain allowlist before Response.seeOther()",

        // ── Quarkus — A02 Cryptographic Failures ─────────────────────────────

        "QuarkusSmallryeJwtInsecure" to
            "mp.jwt.verify.algorithm=RS256 with mp.jwt.verify.publickey.location=/META-INF/public.key",

        // ── Quarkus — A03 Injection ───────────────────────────────────────────

        "PanacheRawQuery" to
            """Entity.find("field = ?1 and value > ?2", param1, param2) — use positional params""",

        "QuarkusMissingBeanValidation" to
            """Add @Valid before the entity parameter: fun create(@Valid @RequestBody dto: Dto)""",

        // ── Quarkus — A05 Security Misconfiguration ───────────────────────────

        "QuarkusBuildTimeSecretLeak" to
            """@ConfigProperty(name = "my.secret") val secret: String // read from Vault or .env""",

        "QuarkusUnsafeHeader" to
            """headerValue.replace("\n", "").replace("\r", "") before addHeader()""",

        "QuarkusCorsPermissiveConfig" to
            "quarkus.http.cors.origins=https://your-app.com (replace wildcard)",

        "QuarkusDevServicesInProd" to
            "%prod.quarkus.devservices.enabled=false (or remove the property entirely)",

        // ── Quarkus — A07 Identification and Authentication Failures ──────────

        "QuarkusHardcodedConfigSecret" to
            """@ConfigProperty(name = "app.secret") val secret: String // inject from env or Vault""",

        "QuarkusOidcInsecureConfig" to
            "quarkus.oidc.tls.verification=required (default; never set to none or certificate-validation)",

        "QuarkusHardcodedDatasourcePassword" to
            """quarkus.datasource.password=${"$"}{DB_PASSWORD} // read from environment""",

        // ── Quarkus — A08 Software and Data Integrity ─────────────────────────

        "QuarkusReflectionUnsafe" to
            "@RegisterForReflection(targets = [MyDto::class]) — limit to the exact classes needed",

        // ── Dropwizard — A01 Broken Access Control ────────────────────────────

        "DropwizardMissingAuth" to
            "Add @Auth User user parameter or @RolesAllowed(\"user\") to every JAX-RS method",

        "DropwizardOpenRedirect" to
            "Validate redirect URI host against trusted allowlist before Response.seeOther(URI(url))",

        // ── Dropwizard — A02 Cryptographic Failures ───────────────────────────

        "InsecureTlsProtocol" to
            """setSupportedProtocols(arrayOf("TLSv1.2", "TLSv1.3"))""",

        "DropwizardUnencryptedJwtSecret" to
            """val secret = System.getenv("JWT_SECRET") ?: error("JWT_SECRET not set")""",

        // ── Dropwizard — A03 Injection ────────────────────────────────────────

        "DropwizardSelfValidatingEL" to
            "Use a static message string in buildConstraintViolationWithTemplate() — never user input",

        // ── Dropwizard — A05 Security Misconfiguration ────────────────────────

        "InsecureCookie" to
            "NewCookie(name, value, path, domain, comment, maxAge, secure = true, httpOnly = true)",

        // ── Ktor — A01 Broken Access Control ──────────────────────────────────

        "KtorMissingAuth" to
            """authenticate("jwt") { get("/protected") { ... } }""",

        "KtorInsecureRedirect" to
            "Validate redirectUrl host against allowlist before call.respondRedirect(redirectUrl)",

        // ── Ktor — A02 Cryptographic Failures ────────────────────────────────

        "KtorBasicAuthInsecure" to
            "Replace basic auth with JWT or session auth; if Basic is required, enforce HTTPS",

        // ── Ktor — A03 Injection ──────────────────────────────────────────────

        "KtorXssResponse" to
            "call.respondText(content.escapeHTML(), ContentType.Text.Html) // escape before rendering",

        // ── Ktor — A05 Security Misconfiguration ──────────────────────────────

        "KtorInsecureCookieSession" to
            "sessions { cookie<S>(\"S\") { transform(SessionTransportTransformerEncrypt(encKey, signKey)) } }",

        "KtorPermissiveCors" to
            """cors { allowHost("your-app.com", schemes = listOf("https")) } // remove anyHost()""",

        "KtorClearTextCookie" to
            "Cookie(name, value, secure = true, httpOnly = true)",

        // ── Ktor — A07 Identification and Authentication Failures ─────────────

        "KtorHardcodedSecretKey" to
            """val key = System.getenv("SESSION_KEY")?.toByteArray() ?: error("SESSION_KEY not set")""",

        "KtorHardcodedPasswordComparison" to
            "BCrypt.checkpw(credentials.password, storedHash) // never compare plaintext passwords",
    )

    /** Returns the fix hint for a given rule ID, or null if not mapped. */
    fun forRule(ruleId: String): String? = MAP[ruleId]
}
