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

        // ── Spring Boot batch 3 ───────────────────────────────────────────────

        "SpringBootNoOpPasswordEncoder" to
            "@Bean fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder() — never use NoOpPasswordEncoder",

        "SpringBootHardcodedValueDefault" to
            "Remove the default value and let the app fail fast: @Value(\"\${jwt.secret}\")",

        "SpringBootCookieNotHttpOnly" to
            "cookie.isHttpOnly = true — or ResponseCookie.from(name, value).httpOnly(true).secure(true).build()",

        "SpringBootInsecureFileUpload" to
            """val safe = UUID.randomUUID().toString() + ".${"\${"}ext${"}"}"; file.transferTo(File(uploadDir, safe))""",

        "SpringBootRequestBodyAnyType" to
            "Replace @RequestBody body: Any with a concrete DTO class to prevent polymorphic deserialization",

        "SpringBootExceptionBodyLeak" to
            "return ResponseEntity.status(500).body(mapOf(\"error\" to \"Internal server error\"))",

        // ── Quarkus — A01 Broken Access Control ──────────────────────────────
        "QuarkusSystemExit" to
                "Let the container or orchestrator (Kubernetes) handle the lifecycle — avoid manual System.exit()",

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

        // ── Quarkus Batch 2 ───────────────────────────────────────────────────

        "QuarkusRestClientInsecureUrl" to
            "@RegisterRestClient(configKey=\"svc\") and set %prod.quarkus.rest-client.svc.url=https://...",

        "QuarkusGraphQLNoAuth" to
            "@GraphQLApi @RolesAllowed(\"user\") class MyApi — add access-control annotation to the class",

        "QuarkusReactiveRouteNoAuth" to
            "@Route(path=\"/x\") @Authenticated fun handle(rc: RoutingContext) — annotate every reactive route",

        "QuarkusRedisInsecure" to
            "Use quarkus.redis.hosts=rediss://host:6380 (double-s) for TLS-encrypted Redis connections",

        "QuarkusMongoInsecure" to
            "Use mongodb+srv://host/db or append ?tls=true to quarkus.mongodb.connection-string",

        "QuarkusOidcAudienceMissing" to
            "Set quarkus.oidc.token.audience=my-service-name to reject tokens issued for other services",

        "QuarkusGrpcInsecure" to
            "Remove plain-text=true and set quarkus.grpc.clients.svc.ssl.trust-certificate=ca.pem",

        "QuarkusNativeQueryInjection" to
            "em.createNativeQuery(\"SELECT * FROM t WHERE id = :id\").setParameter(\"id\", id)",

        "QuarkusPathParamInjection" to
            "Use positional params: User.find(\"name = ?1\", name) instead of string interpolation",

        "QuarkusMultipartInsecure" to
            "Set quarkus.http.limits.max-body-size=10M to prevent resource exhaustion via large uploads",

        "QuarkusSmallRyeHealthInsecure" to
            "Use %dev.quarkus.smallrye-health.ui.enable=true — omit or disable in default/prod profile",

        "QuarkusSwaggerUiInProd" to
            "Use %dev.quarkus.swagger-ui.always-include=true — never set always-include=true globally",

        "QuarkusConfigPasswordLeak" to
            "Remove defaultValue from @ConfigProperty for secrets — require the env var to be explicitly set",

        // ── Quarkus batch 3 ───────────────────────────────────────────────────

        "QuarkusFormCsrfMissing" to
            "Add @HeaderParam(\"X-CSRF-Token\") or use the Quarkus CSRF Reactive extension",

        "QuarkusUnsafeSecurityContext" to
            "if (!ctx.isUserInRole(\"admin\")) throw ForbiddenException() — always check the injected context",

        "QuarkusSensitiveQueryParam" to
            "Pass credentials in the request body or Authorization header, not as URL query parameters",

        "QuarkusMassAssignment" to
            "Create a DTO that exposes only fields the client is allowed to set, not the domain entity directly",

        "QuarkusInsecureCookie" to
            "NewCookie.Builder(name).secure(true).httpOnly(true).sameSite(SameSite.STRICT).build()",

        "QuarkusInsecureFileUpload" to
            "val safe = UUID.randomUUID().toString() + ext; File(uploadDir, safe)",

        "QuarkusHardcodedConfigPropertyDefault" to
            "@ConfigProperty(name = \"jwt.secret\") — omit defaultValue so the app fails fast when absent",

        "QuarkusJsonbUnsafeDeserialization" to
            "Replace Object::class.java with a concrete DTO class in Jsonb.fromJson()",

        "QuarkusExceptionMessageLeak" to
            "Response.serverError().entity(mapOf(\"error\" to \"Internal error\")).build()",

        "QuarkusPasswordInLog" to
            "Log only non-sensitive identifiers (userId, requestId) — never log credentials or secrets",

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

        // ── Dropwizard — A03 Injection ────────────────────────────────────────

        "DropwizardJdbiSqlInjection" to
            "@SqlQuery(\"SELECT * FROM t WHERE id = :id\") fun find(@Bind(\"id\") id: Long): T",

        "DropwizardMissingBeanValidation" to
            "Add @Valid to the request body parameter: fun create(@Valid @NotNull req: CreateReq): Response",

        "DropwizardXssResponse" to
            "HTML-encode output: StringEscapeUtils.escapeHtml4(value) or switch to APPLICATION_JSON",

        // ── Dropwizard — A05 Security Misconfiguration ────────────────────────

        "InsecureCookie" to
            "NewCookie(name, value, path, domain, comment, maxAge, secure = true, httpOnly = true)",

        "DropwizardAdminConnectorExposed" to
            "Set server.adminConnectors[0].bindHost=127.0.0.1 in production configuration",

        "DropwizardInsecureMultipart" to
            "Set server.maxRequestEntitySize=10MiB to prevent resource-exhaustion via large uploads",

        // ── Dropwizard — A07 Identification and Authentication Failures ────────

        "DropwizardHardcodedToken" to
            "val apiKey: String = System.getenv(\"API_KEY\") ?: error(\"API_KEY env var not set\")",

        "DropwizardDatabasePassword" to
            "Use database.password=\${DB_PASSWORD} and inject the value via the deployment environment",

        // ── Dropwizard — A08 Software and Data Integrity Failures ─────────────

        "DropwizardJacksonPolymorphism" to
            "mapper.activateDefaultTypingAsProperty(ptv, OBJECT_AND_NON_CONCRETE, \"@class\")",

        // ── Dropwizard — A09 Security Logging and Monitoring Failures ─────────

        "DropwizardSensitiveDataLogging" to
            "Log user ID or action only — never the credential itself: logger.info(\"Auth for userId={}\", id)",

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

        // ── Spring Boot (new batch) ───────────────────────────────────────────

        "AsyncSecurityContextLoss" to
            "Wrap executor: @Bean fun exec() = DelegatingSecurityContextAsyncTaskExecutor(ThreadPoolTaskExecutor())",

        "FeignClientInsecureUrl" to
            "@FeignClient(name = \"svc\", url = \"https://svc\") or remove url and use service discovery",

        "JwtSecretInProperties" to
            """spring.security.oauth2.resourceserver.jwt.secret=${"$"}{JWT_SECRET} // inject from env""",

        "EntityManagerJpqlInjection" to
            "em.createQuery(\"SELECT u FROM User u WHERE name = :n\").setParameter(\"n\", value)",

        "KafkaTrustedPackagesWildcard" to
            "spring.kafka.consumer.properties.spring.json.trusted.packages=com.myapp.dto",

        "KafkaInsecureProtocol" to
            "spring.kafka.security.protocol=SASL_SSL (and configure keystore/truststore)",

        "SpringSecurityDebugEnabled" to
            "Remove debug=true from @EnableWebSecurity — it is safe to omit entirely in production",

        "H2ConsoleEnabled" to
            "%prod.spring.h2.console.enabled=false or simply remove the property (default is false)",

        "InsecureRememberMe" to
            """http.rememberMe().key(System.getenv("REMEMBER_ME_KEY") ?: error("key not set"))""",

        "ShowSqlEnabled" to
            "Use %dev.spring.jpa.show-sql=true and omit the key in default/prod profile",

        "RestTemplateSsrf" to
            "val host = URI(url).host; require(host in allowedHosts) before restTemplate.getForObject(url, ...)",

        // ── Spring Boot Batch 2 ───────────────────────────────────────────────

        "OAuth2ClientSecretInProperties" to
            "Use spring.security.oauth2.client.registration.google.client-secret=\${GOOGLE_CLIENT_SECRET}",

        "HardcodedDatasourcePassword" to
            "Use spring.datasource.password=\${DB_PASSWORD} and set the variable in the deployment environment",

        "SpringActuatorShutdownEnabled" to
            "Remove management.endpoint.shutdown.enabled=true and 'shutdown' from exposure.include",

        "CloudConfigInsecureUri" to
            "Use spring.cloud.config.uri=https://config-server to prevent credentials sent in cleartext",

        "SpringDataSortInjection" to
            "val allowed = setOf(\"name\",\"email\"); require(field in allowed); Sort.by(field)",

        "UnvalidatedForward" to
            "Use a whitelist map: val targets = mapOf(\"home\" to \"/home.jsp\"); forward to targets[key]!!",

        "SpringCacheableSensitive" to
            "Remove @Cacheable or encrypt the cached value: redisTemplate.opsForValue().set(key, encrypt(value))",

        "CrossOriginCredentialsWildcard" to
            "@CrossOrigin(origins = [\"https://app.example.com\"], allowCredentials = \"true\")",

        "PermitAllAdminPath" to
            ".requestMatchers(\"/admin/**\").hasRole(\"ADMIN\") — never use permitAll() for admin paths",

        "SecurityLoggingVerbose" to
            "Use %dev.logging.level.org.springframework.security=DEBUG — omit the key in default/prod profile",

        // ── Ktor — A01 Broken Access Control ──────────────────────────────────

        "KtorCsrfMissing" to
            "install(CSRF) { allowHeader(HttpHeaders.Origin) } — add CSRF plugin or validate Origin/X-Requested-With",

        // ── Ktor — A02 Cryptographic Failures ────────────────────────────────

        "KtorWeakJwtSecret" to
            """val secret = System.getenv("JWT_SECRET") ?: error("JWT_SECRET not set"); Algorithm.HMAC256(secret)""",

        // ── Ktor — A03 Injection ──────────────────────────────────────────────

        "KtorExposedOrmInjection" to
            "Use Exposed's typesafe DSL: Users.select { Users.name eq param } — avoid exec() with string templates",

        "KtorSensitiveRouteParam" to
            "Never log or expose route params named password/token/secret — read from body or headers instead",

        // ── Ktor — A05 Security Misconfiguration ──────────────────────────────

        "KtorSecurityHeadersMissing" to
            """install(DefaultHeaders) { header("X-Frame-Options", "DENY"); header("X-Content-Type-Options", "nosniff") }""",

        "KtorSslRedirectMissing" to
            "install(HttpsRedirect) { sslPort = 443 } — redirect all HTTP traffic to HTTPS",

        "KtorRateLimitingMissing" to
            "install(RateLimit) { register(RateLimitName(\"login\")) { rateLimiter(limit = 5, refillPeriod = 1.minutes) } }",

        "KtorSessionCookieDomainMissing" to
            "cookie.domain = \"app.example.com\" — restrict session cookie to known domain to prevent subdomain hijack",

        // ── Ktor — A07 Identification and Authentication Failures ─────────────

        "KtorHardcodedSecretKey" to
            """val key = System.getenv("SESSION_KEY")?.toByteArray() ?: error("SESSION_KEY not set")""",

        "KtorHardcodedPasswordComparison" to
            "BCrypt.checkpw(credentials.password, storedHash) // never compare plaintext passwords",

        "KtorHardcodedDatabasePassword" to
            """Database.connect(url, password = System.getenv("DB_PASS") ?: error("DB_PASS not set"))""",

        // ── Ktor — A09 Security Logging and Monitoring Failures ───────────────

        "KtorLoggingCredentials" to
            "Remove sensitive keywords from log statements — log only non-sensitive identifiers (userId, requestId)",
    )

    /** Returns the fix hint for a given rule ID, or null if not mapped. */
    fun forRule(ruleId: String): String? = MAP[ruleId]
}
