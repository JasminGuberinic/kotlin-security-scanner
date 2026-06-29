# kotlin-security-scanner

[![CI](https://github.com/JasminGuberinic/kotlin-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/JasminGuberinic/kotlin-security-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Kotlin](https://img.shields.io/badge/kotlin-2.0.10-purple.svg)](https://kotlinlang.org)
[![Detekt](https://img.shields.io/badge/detekt-1.23.7-blue.svg)](https://detekt.dev)
[![Rules](https://img.shields.io/badge/rules-209-brightgreen.svg)](#owasp-top-10-coverage)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.jasminguberinic/scanner-core.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.jasminguberinic/scanner-core)

**Kotlin SAST — Detekt plugin with 209 rules that detects OWASP Top 10 security vulnerabilities in Spring Boot, Quarkus, Dropwizard, Ktor, Micronaut, and Vert.x applications at compile time, in your IDE, with zero infrastructure.**

> **FindSecBugs** works on JVM bytecode and misses Kotlin-specific patterns: coroutines, scope functions, Kotlin DSLs.  
> **SonarQube** security rules require a paid tier or a running server.  
> **CodeQL** requires a full build pipeline and cloud connectivity.  
> This tool runs as a Gradle plugin, offline, on every build, in every developer's environment.

---

## Quick Start

All modules are published to **Maven Central** under `io.github.jasminguberinic`.

```kotlin
// build.gradle.kts
plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

dependencies {
    // Core rules — works with any Kotlin project
    detektPlugins("io.github.jasminguberinic:scanner-core:0.3.0")

    // Pick the module(s) for your framework — combine as many as you like
    detektPlugins("io.github.jasminguberinic:scanner-spring-boot:0.3.0")
    // detektPlugins("io.github.jasminguberinic:scanner-quarkus:0.3.0")
    // detektPlugins("io.github.jasminguberinic:scanner-dropwizard:0.3.0")
    // detektPlugins("io.github.jasminguberinic:scanner-ktor:0.3.0")
    // detektPlugins("io.github.jasminguberinic:scanner-micronaut:0.3.0")
    // detektPlugins("io.github.jasminguberinic:scanner-vertx:0.3.0")

    // ...or pull everything in one go:
    // detektPlugins("io.github.jasminguberinic:scanner-all:0.3.0")
}

detekt {
    buildUponDefaultConfig = true
}
```

Run:

```bash
./gradlew detekt
```

That's it — no server, no account, no extra infrastructure. **Every rule is active by
default**, so findings appear on the first `./gradlew detekt` with no per-rule setup. To
silence a specific rule, set it to `active: false` in your `detekt.yml`:

```yaml
security-core:
  RegexInjection:
    active: false   # opt out of an individual rule
```

The rules run on every build and in your IDE through the Detekt plugin.

---

## GitHub Code Scanning (SARIF)

Detekt outputs SARIF natively. Drop this into `.github/workflows/security.yml`:

```yaml
- uses: actions/checkout@v4
- name: Run Kotlin security scan
  run: ./gradlew detekt
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: build/reports/detekt/
```

Results appear inline on pull request diffs — no account, no server, no cost (free for public repos).

---

## OWASP Top 10 coverage

**209 rules** across 7 modules. Every rule has positive, negative, and cross-rule isolation tests
(1289 tests, all green) and is verified end-to-end against intentionally vulnerable fixtures with a
companion safe-code fixture proving zero false positives. The tables below highlight representative
rules per module.

### Core — any Kotlin project (`scanner-core`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `JaxrsOpenRedirectRule` | A01 | `Response.seeOther(URI(variable))` — open redirect (JAX-RS / Micronaut, all frameworks) |
| `WeakCipherModeRule` | A02 | ECB mode, DES, RC4, RC2, Blowfish in `Cipher.getInstance()` |
| `WeakHashAlgorithmRule` | A02 | `MessageDigest.getInstance("MD5"\|"SHA-1")` |
| `TrustAllCertsRule` | A02 | Empty `X509TrustManager` — accepts any certificate |
| `HardcodedIvRule` | A02 | `IvParameterSpec(byteArrayOf(...))` with hardcoded bytes |
| `WeakRsaKeyRule` | A02 | `KeyPairGenerator.initialize(≤1024)` |
| `JwtNoneAlgorithmRule` | A02 | `.signWith(NONE)` / `Algorithm.none()` — JWT signature disabled |
| `JwtWeakSecretRule` | A02 | `HMAC256(literal)` / `signWith(literal)` — hardcoded JWT secret |
| `UnsafeCryptoPaddingOracleRule` | A02 | `Cipher.getInstance("AES/CBC/PKCS5Padding")` — padding oracle risk |
| `InsecurePasswordStorageRule` | A02 | `MessageDigest`/`DigestUtils` for passwords — use BCrypt/Argon2 |
| `SqlInjectionRule` | A03 | String interpolation or `+` inside SQL queries |
| `LdapInjectionRule` | A03 | Dynamic strings in `ctx.search()` / `ctx.bind()` |
| `JndiInjectionRule` | A03 | `ctx.lookup(nonLiteral)` — remote JNDI code execution |
| `XpathInjectionRule` | A03 | Dynamic XPath expressions in `xpath.evaluate()` |
| `ReflectionInjectionRule` | A03 | `Class.forName(nonLiteral)` — attacker-chosen class loading |
| `PathTraversalRule` | A03 | `File()` / `Paths.get()` with non-literal input |
| `CommandInjectionRule` | A03 | `Runtime.exec()` / `ProcessBuilder()` with dynamic args |
| `XxeInjectionRule` | A03 | `DocumentBuilderFactory.newInstance()` without DTD disabled |
| `GroovyScriptInjectionRule` | A03 | `GroovyShell().evaluate(nonLiteral)` — script RCE |
| `RegexDenialOfServiceRule` | A06 | `Regex("(a+)+")` — catastrophic backtracking / ReDoS |
| `HardcodedCredentialsRule` | A07 | Hardcoded passwords, API keys, tokens in source code |
| `InsecureRandomRule` | A07 | `java.util.Random` / `ThreadLocalRandom` for security values |
| `HardcodedAwsCredentialsRule` | A07 | AWS access key literals matching `AKIA/ASIA/AROA/AIDA[0-9A-Z]{16}` |
| `InsecureDeserializationRule` | A08 | `ObjectInputStream` — unsafe with untrusted data |
| `JacksonUnsafeDeserializationRule` | A08 | `enableDefaultTyping()` / `@JsonTypeInfo(use=Id.CLASS)` |
| `XmlMapperUnsafeRule` | A08 | `XmlMapper()` constructor — unsafe XML deserialization |
| `KotlinxSerializationSensitiveFieldRule` | A08 | `@Serializable` class with password/secret field missing `@Transient` |
| `SensitiveDataLoggingRule` | A09 | Passwords or tokens interpolated into log statements |
| `LogForgingRule` | A09 | Request input interpolated into logs — CR/LF log forging |
| `SsrfRule` | A10 | `URL()` / `URI()` constructed from a non-literal value |
| `GoogleApiKeyRule` | A07 | Hardcoded Google/Firebase API key (`AIza…`) |
| `SlackTokenRule` | A07 | Hardcoded Slack token (`xoxb-`/`xoxp-`/…) |
| `GitHubTokenRule` | A07 | Hardcoded GitHub token (`ghp_`/`github_pat_`) |
| `StripeSecretKeyRule` | A07 | Hardcoded Stripe live secret key (`sk_live_`) |
| `HardcodedJwtTokenRule` | A07 | Signed JWT bearer token literal in source |
| `HardcodedJdbcCredentialsRule` | A07 | JDBC URL embedding user/password |
| `InsecureSslContextRule` | A02 | `SSLContext.getInstance("SSLv3"\|"TLSv1.1")` |
| `ZipSlipRule` | A03 | ZipEntry name resolved into a path — archive traversal |
| `RegexInjectionRule` | A06 | `Pattern.compile(userInput)` — ReDoS via injected pattern |
| `InsecureFilePermissionsRule` | A05 | `PosixFilePermissions.fromString("rwxrwxrwx")` / world-writable |
| `PredictableTempFileRule` | A01 | `File("/tmp/…")` — predictable temp file location |

### Spring Boot (`scanner-spring-boot`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `MissingAuthorizationRule` | A01 | `@GetMapping` etc. without `@PreAuthorize` or `@Secured` |
| `DisabledHttpSecurityRule` | A01 | `anyRequest().permitAll()` in `SecurityFilterChain` |
| `ReactiveSecurityContextHolderRule` | A01 | ThreadLocal `SecurityContextHolder` in WebFlux — empty context, broken auth |
| `ReactivePermitAllExchangeRule` | A01 | `anyExchange().permitAll()` / admin `pathMatchers(...).permitAll()` (reactive) |
| `WebFluxBlockingCallRule` | A05 | `.block()` inside a `Mono`/`Flux` method — starves the event loop (DoS) |
| `OpenRedirectRule` | A01 | `"redirect:" + variable` in `@Controller` methods |
| `CsrfTokenLeakRule` | A01 | `model.addAttribute("csrf/xsrf...", token)` exposes CSRF token |
| `CoroutineSecurityContextLossRule` | A01 | `suspend fun` with `@PreAuthorize` — security context silently dropped |
| `AsyncSecurityContextLossRule` | A01 | `@Async` method reading `SecurityContextHolder` — context lost across threads |
| `FeignClientInsecureUrlRule` | A01 | `@FeignClient(url = "http://...")` — credentials over cleartext channel |
| `InsecurePasswordEncoderRule` | A02 | `NoOpPasswordEncoder`, `Md5PasswordEncoder` |
| `WeakBcryptRoundsRule` | A02 | `BCryptPasswordEncoder(strength < 10)` — brute-forceable offline |
| `JwtExpirationMissingRule` | A02 | JWT `.compact()` without `.setExpiration()` — tokens never expire |
| `MissingHttpsRedirectRule` | A02 | `SecurityFilterChain` without `requiresChannel().requiresSecure()` |
| `InsecureRedisConnectionRule` | A02 | `RedisStandaloneConfiguration`/`LettuceConnectionFactory` without TLS |
| `InsecureSmtpConfigRule` | A02 | `spring.mail.smtp.starttls.enable=false` in `application.properties` |
| `JwtSecretInPropertiesRule` | A02 | JWT signing secret hardcoded in `application.properties` |
| `SpelInjectionRule` | A03 | `parseExpression(nonLiteral)` — SpEL RCE |
| `ResponseSplittingRule` | A03 | `response.addHeader(name, nonLiteral)` — CR/LF injection |
| `ELInjectionRule` | A03 | `ELProcessor.eval(nonLiteral)` — EL expression RCE |
| `SpringDataMongoInjectionRule` | A03 | `Criteria.where(nonLiteral)` — MongoDB injection |
| `ThymeleafSSTIRule` | A03 | `templateEngine.process(nonLiteral, ctx)` — Thymeleaf SSTI |
| `EntityManagerJpqlInjectionRule` | A03 | `createQuery`/`createNativeQuery` with dynamic string — JPQL/SQL injection |
| `MassAssignmentRule` | A04 | `@RequestBody` on a JPA `@Entity` class |
| `SpringCsrfDisabledRule` | A05 | `.csrf { disable() }` / `.csrf().disable()` |
| `PermissiveCorsRule` | A05 | `allowedOrigins("*")` in CORS config |
| `InsecureActuatorExposureRule` | A05 | `management.endpoints.web.exposure.include=*` in properties |
| `SecurityHeadersMissingRule` | A05 | `SecurityFilterChain` without `.headers{}` (no CSP, X-Frame-Options) |
| `ExceptionDetailsExposedRule` | A05 | `@ExceptionHandler` returning `e.message` — leaks internals to client |
| `HttpMethodOverrideRule` | A05 | `HiddenHttpMethodFilter` re-enabled — bypasses method-specific CSRF |
| `KafkaTrustedPackagesWildcardRule` | A05 | `spring.json.trusted.packages=*` — arbitrary class deserialization (CVE-2023-34040) |
| `KafkaInsecureProtocolRule` | A05 | `spring.kafka.*.security.protocol=PLAINTEXT` — unencrypted broker traffic |
| `SpringSecurityDebugEnabledRule` | A05 | `@EnableWebSecurity(debug=true)` — logs all requests and auth decisions |
| `H2ConsoleEnabledRule` | A05 | `spring.h2.console.enabled=true` outside dev/test — exposes SQL console |
| `InsecureRememberMeRule` | A07 | `rememberMe().key("literal")` — hardcoded cookie-signing secret |
| `ShowSqlEnabledRule` | A09 | `spring.jpa.show-sql=true` / Hibernate SQL logging — leaks schema to logs |
| `WebClientSSRFRule` | A10 | `WebClient.create(nonLiteral)` — WebFlux SSRF |
| `RestTemplateSsrfRule` | A10 | `restTemplate.getForObject/exchange(variable, ...)` — RestTemplate SSRF |

### Quarkus (`scanner-quarkus`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `QuarkusMissingAuthRule` | A01 | JAX-RS `@GET` etc. without `@RolesAllowed` / `@Authenticated` |
| `QuarkusPermitAllSensitiveRule` | A01 | `@PermitAll` on `@DELETE` / `@PUT` endpoints |
| `QuarkusJsonBeforeAuthRule` | A01 | CVE-2023-6267: `@Path` class with method-only security — JSON parsed before auth |
| `QuarkusSmallryeJwtInsecureRule` | A02 | `mp.jwt.verify.algorithm=none` or hardcoded `mp.jwt.verify.secret.value` |
| `PanacheRawQueryRule` | A03 | `PanacheEntity.find(interpolated)` — NoSQL/ORM injection |
| `QuarkusMissingBeanValidationRule` | A03 | `@POST`/`@PUT` entity parameter without `@Valid` — input skips validation |
| `QuarkusBuildTimeSecretLeakRule` | A05 | Hardcoded secret in `application.properties` — bundled into native image |
| `QuarkusUnsafeHeaderRule` | A05 | `Response.header(name, nonLiteral)` — response splitting |
| `QuarkusCorsPermissiveConfigRule` | A05 | `quarkus.http.cors.origins=*` — allows all cross-origin requests |
| `QuarkusDevServicesInProdRule` | A05 | `quarkus.devservices.enabled=true` in production profile |
| `QuarkusHardcodedConfigSecretRule` | A07 | `@ConfigProperty(defaultValue="hardcoded-secret")` |
| `QuarkusOidcInsecureConfigRule` | A07 | `quarkus.oidc.tls.verification=none` or hardcoded OIDC secret |
| `QuarkusHardcodedDatasourcePasswordRule` | A07 | `quarkus.datasource.password` hardcoded — use env var reference |
| `QuarkusReflectionUnsafeRule` | A08 | `@RegisterForReflection` on `Serializable` with `readObject` |

### Dropwizard (`scanner-dropwizard`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `DropwizardMissingAuthRule` | A01 | JAX-RS `@GET` etc. without `@RolesAllowed`, `@DenyAll`, or `@Auth` |
| `InsecureTlsProtocolRule` | A02 | TLS 1.0, TLS 1.1, SSLv2, SSLv3 in TLS configuration |
| `DropwizardUnencryptedJwtSecretRule` | A02 | `setSecretProvider(literal)` — hardcoded JWT secret |
| `DropwizardSelfValidatingELRule` | A03 | `buildConstraintViolationWithTemplate(nonLiteral)` — EL injection (CVE-2020-5245) |
| `InsecureCookieRule` | A05 | `NewCookie(name, value)` without `secure=true` |

### Ktor (`scanner-ktor`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `KtorMissingAuthRule` | A01 | `routing {}` block with no `authenticate {}` wrapper — all routes public |
| `KtorInsecureRedirectRule` | A01 | `call.respondRedirect(variable)` — open redirect via dynamic URL |
| `KtorBasicAuthInsecureRule` | A02 | `basic { }` authentication — credentials base64-encoded over wire |
| `KtorXssResponseRule` | A03 | `call.respondText(dynamic, ContentType.Text.Html)` — reflected XSS |
| `KtorInsecureCookieSessionRule` | A05 | `install(Sessions) { cookie<T>() }` without `transform(Encrypt...)` — forgeable session |
| `KtorPermissiveCorsRule` | A05 | `install(CORS) { anyHost() }` — cross-origin requests from any domain |
| `KtorClearTextCookieRule` | A05 | `Cookie(name, value)` without `secure = true` — sent over plain HTTP |
| `KtorHardcodedSecretKeyRule` | A07 | `SessionTransportTransformerEncrypt("literal", ...)` — hardcoded session key |
| `KtorHardcodedPasswordComparisonRule` | A07 | `credentials.password == "literal"` — plaintext hardcoded password |

### Micronaut (`scanner-micronaut`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `MicronautMissingSecuredRule` | A01 | `@Get`/`@Post` controller method without `@Secured` |
| `MicronautWebSocketNoAuthRule` | A01 | `@ServerWebSocket` endpoint without `@Secured` |
| `MicronautCacheableSensitiveRule` | A01 | `@Cacheable` on a `@Secured` method — cross-user cache leak |
| `MicronautRetryOnAuthRule` | A07 | `@Retryable` on a login/auth method — enables brute force |
| `MicronautManagementEndpointInsecureRule` | A05 | `@Endpoint` `@Read`/`@Write` without `@Secured` |
| `MicronautInsecureHttpClientRule` | A02 | `@Client("http://...")` — cleartext service-to-service traffic |
| `MicronautGrpcInsecureRule` | A02 | gRPC `usePlaintext()` — disables channel TLS |
| `MicronautHardcodedSecretRule` | A07 | `@Value("${...:hardcoded}")` — secret baked into config default |
| `MicronautSensitiveQueryParamRule` | A03 | `@QueryValue password` — credentials in URL / access logs |
| `MicronautExceptionMessageLeakRule` | A09 | `@Error` handler returning `exception.message` — internals leak |
| `MicronautBodyAnyTypeRule` | A04 | `@Body body: Any` — unbounded deserialization target |

### Vert.x (`scanner-vertx`)

| Rule | OWASP 2021 | What it catches |
|---|---|---|
| `VertxEventBusBridgeOpenRule` | A01 | SockJS bridge `setAddressRegex(".*")` — exposes the whole event bus |
| `VertxTrustAllCertsRule` | A02 | `setTrustAll(true)` / `setVerifyHost(false)` — disables TLS verification |
| `VertxCorsWildcardRule` | A05 | `CorsHandler.create(".*")` / `addOrigin("*")` — any-origin CORS |
| `VertxBodyHandlerNoLimitRule` | A05 | `BodyHandler.create()` without `setBodyLimit` — unbounded body (DoS) |
| `VertxInsecureCookieRule` | A05 | `Cookie.cookie(...).setSecure(false)` — cookie over plain HTTP |

---

## Why not FindSecBugs / SonarQube?

| Capability | FindSecBugs | SonarQube | **kotlin-security-scanner** |
|---|---|---|---|
| Kotlin-native (PSI/AST) | ❌ Bytecode only | ⚠️ Partial | ✅ |
| Coroutine security patterns | ❌ Impossible | ❌ | ✅ |
| `let`/`run`/`apply` taint tracking | ❌ | ❌ | ✅ |
| Spring Boot / Quarkus / Dropwizard / Ktor / Micronaut / Vert.x rules | ⚠️ Java only | ⚠️ Paid tier | ✅ |
| Config file scanning (`.properties`/`.yml`) | ❌ | ❌ | ✅ |
| Infrastructure needed | ❌ | ✅ Server | ❌ |
| Cost | Free | Free / Paid | Free |
| IDE integration (Detekt) | ❌ | ❌ | ✅ |

FindSecBugs misses Kotlin-specific patterns because:
- Kotlin scope functions (`let`, `run`, `apply`, `also`) compile to lambda bytecode that breaks taint analysis
- `suspend fun` — coroutine desugaring makes authorization annotations invisible at bytecode level
- Kotlin's PSI nodes (`KtStringTemplateExpression`, `KtDotQualifiedExpression`) have no direct bytecode equivalent

See [FindSecBugs issue #432](https://github.com/find-sec-bugs/find-sec-bugs/issues/432) and [Kotlin taint analysis limitations](https://arxiv.org/abs/2207.09379).

---

## Example output

```
src/main/kotlin/com/example/UserService.kt:42:9
  String interpolation in SQL — use :namedParam or ? placeholders [SqlInjection]

src/main/kotlin/com/example/AuthConfig.kt:18:5
  anyRequest().permitAll() makes all endpoints public [DisabledHttpSecurity]

src/main/kotlin/com/example/CryptoService.kt:31:9
  AES/ECB — use AES/GCM/NoPadding instead [WeakCipherMode]

src/main/kotlin/com/example/JwtConfig.kt:12:5
  signWith(NONE) disables JWT signature — use HS256/RS256 [JwtNoneAlgorithm]

src/main/kotlin/com/example/UserController.kt:25:5
  suspend fun with @PreAuthorize — security context is silently dropped [CoroutineSecurityContextLoss]
```

---

## Architecture

Multi-module — add only what your project uses.

```
kotlin-security-scanner/
├── scanner-core/            # Framework-agnostic rules (any Kotlin project)
│   └── core/
│       ├── SecurityRule.kt        # Base class — reportAt() helper
│       └── DetectionPatterns.kt   # All patterns, single source of truth
│
├── scanner-spring-boot/     # Spring MVC / Spring Security rules
├── scanner-quarkus/         # Quarkus / MicroProfile / JAX-RS rules
├── scanner-dropwizard/      # Dropwizard / JAX-RS rules
├── scanner-ktor/            # Ktor routing / session / CORS rules
├── scanner-micronaut/       # Micronaut security / config / client rules
├── scanner-vertx/           # Vert.x TLS / CORS / event-bus / cookie rules
└── scanner-all/             # Convenience bundle (all modules)
```

Design principles:
- Every rule lives in the OWASP package that matches its category (`a01/`–`a10/`)
- All patterns in `DetectionPatterns.kt` — rules never hardcode strings
- No coupling between rules — each only imports from `core/`
- Three test layers per rule: positive (flag), negative (safe), isolation (other rule's fixture)

---

## Adding rules

The project uses a Claude Code skill for consistent rule contributions:

```
/add-security-rule WeakRsaKeyRule core A02
```

The skill reads the pre-researched backlog in `RULES_BACKLOG.md`, generates the rule class, test class, registers it in the provider and `detekt.yml`, and updates the coverage table — all following the established patterns.

Manual checklist for PRs:
- [ ] Rule in correct `a0X/` package in the right module
- [ ] FindSecBugs ID referenced in rule KDoc
- [ ] Patterns added to `DetectionPatterns.kt`
- [ ] Tests: ≥3 positive, ≥2 negative, 1 isolation
- [ ] `./gradlew test detekt` passes clean

---

## Contributing

```bash
git clone https://github.com/JasminGuberinic/kotlin-security-scanner.git
cd kotlin-security-scanner
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
./gradlew test detekt
```

See [`RULES_BACKLOG.md`](RULES_BACKLOG.md) for the pre-researched rule backlog with 20+ more rules ready to implement.

---

## Stack

| Component | Version |
|---|---|
| Kotlin | 2.0.10 |
| Detekt | 1.23.7 |
| Java | 21 |
| Gradle | 8.x |
| AssertJ | 3.26.3 |

---

## License

Apache License 2.0 — same license as Spring Boot and Detekt.

---

*Inspired by [FindSecBugs](https://find-sec-bugs.github.io), [gosec](https://github.com/securego/gosec), and the [OWASP Top 10](https://owasp.org/Top10/).*
