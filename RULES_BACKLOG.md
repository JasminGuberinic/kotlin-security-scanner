# Rules Backlog

State file for kotlin-security-scanner rule development.
All research is pre-embedded — no doc fetching needed during implementation.

## Status legend
- `[ ]` planned
- `[~]` in progress (current session)
- `[x]` done

---

## How to resume a session

1. Read this file to see what's done and what's next
2. Pick the first `[ ]` rule from a module
3. Run `/add-security-rule` — the skill reads the row and generates everything
4. Check the box, pick the next

Build command: `export JAVA_HOME=/opt/homebrew/opt/openjdk@21 && ./gradlew test detekt`

---

## scanner-core (framework-agnostic)

Existing: WeakCipherModeRule, SqlInjectionRule, PathTraversalRule,
HardcodedCredentialsRule, InsecureRandomRule, SensitiveDataLoggingRule, SsrfRule

| Status | Rule | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|----------------|-----------------|
| `[x]` | WeakCipherModeRule | A02 | ECB_MODE, DES_USAGE | `getInstance("ECB\|DES\|RC4\|Blowfish")` |
| `[x]` | SqlInjectionRule | A03 | SQL_INJECTION_JPA | string interpolation / `+` in SQL |
| `[x]` | PathTraversalRule | A03 | PATH_TRAVERSAL_IN | `File(var)`, `Paths.get(var)` |
| `[x]` | HardcodedCredentialsRule | A07 | HARD_CODE_PASSWORD | credential var = string literal |
| `[x]` | InsecureRandomRule | A07 | PREDICTABLE_RANDOM | `Random()`, `ThreadLocalRandom()` |
| `[x]` | SensitiveDataLoggingRule | A09 | INFORMATION_EXPOSURE | log call + interpolated sensitive keyword |
| `[x]` | SsrfRule | A10 | URLCONNECTION_SSRF_FD | `URL(var)`, `URI(var)` non-literal |
| `[x]` | CommandInjectionRule | A03 | COMMAND_INJECTION | `Runtime.getRuntime().exec(var)`, `ProcessBuilder(listOf(var))` — flag when arg is not all-literal |
| `[x]` | XxeInjectionRule | A03 | XXE_DTD, XXE_SAXPARSER | `DocumentBuilderFactory.newInstance()` / `SAXParserFactory.newInstance()` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| `[x]` | InsecureDeserializationRule | A08 | OBJECT_DESERIALIZATION | `ObjectInputStream(...)` constructor call |
| `[x]` | WeakHashAlgorithmRule | A02 | WEAK_MESSAGE_DIGEST_MD5, WEAK_MESSAGE_DIGEST_SHA1 | `MessageDigest.getInstance("MD5"\|"SHA-1"\|"SHA1")` |
| `[x]` | LdapInjectionRule | A03 | LDAP_INJECTION | string interpolation / `+` inside `search(`, `bind(` call argument |
| `[x]` | XpathInjectionRule | A03 | XPATH_INJECTION | string interpolation / `+` passed to `xpath.evaluate(`, `compile(` |
| `[x]` | JndiInjectionRule | A03 | JNDI_INJECTION | `ctx.lookup(var)` / `ctx.rebind(var)` with any non-literal — remote URL RCE risk |
| `[x]` | ReflectionInjectionRule | A03 | REFLECTOR_BASED_INJECTION | `Class.forName(var)` with non-literal — attacker-chosen class loading |
| `[x]` | TrustAllCertsRule | A02 | WEAK_TRUST_MANAGER | anonymous `X509TrustManager` with empty `checkClientTrusted`/`checkServerTrusted` |
| `[x]` | HardcodedIvRule | A02 | STATIC_IV | `IvParameterSpec(byteArrayOf(...))` with literal byte array — IV must be random |
| `[x]` | WeakRsaKeyRule | A02 | WEAK_KEY_SIZE | `KeyPairGenerator.initialize(size)` where size ≤ 1024 |
| `[x]` | GroovyScriptInjectionRule | A03 | SCRIPT_ENGINE_INJECTION | `GroovyShell().evaluate(var)` / `ScriptEngine.eval(var)` with non-literal |

---

## scanner-spring-boot

Existing: MissingAuthorizationRule, SpringCsrfDisabledRule, PermissiveCorsRule

| Status | Rule | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|----------------|-----------------|
| `[x]` | MissingAuthorizationRule | A01 | SPRING_ENDPOINT | `@GetMapping` etc. without `@PreAuthorize`/`@Secured` |
| `[x]` | SpringCsrfDisabledRule | A05 | SPRING_CSRF_PROTECTION_DISABLED | `.csrf { disable() }` / `.csrf().disable()` |
| `[x]` | PermissiveCorsRule | A05 | PERMISSIVE_CORS | `allowedOrigins("*")` |
| `[x]` | SpelInjectionRule | A03 | SPEL_INJECTION | `ExpressionParser.parseExpression(var)` or `SpelExpressionParser().parseExpression(var)` where arg is non-literal |
| `[x]` | InsecurePasswordEncoderRule | A02 | WEAK_PASSWORD_ENCODER | `NoOpPasswordEncoder.getInstance()`, `new Md5PasswordEncoder()`, `new ShaPasswordEncoder()` |
| `[x]` | MassAssignmentRule | A04 | MASS_ASSIGNMENT | `@RequestBody` on a `@Entity`-annotated class (domain entity used directly as DTO) |
| `[x]` | DisabledHttpSecurityRule | A01 | SPRING_CSRF_PROTECTION_DISABLED | `anyRequest().permitAll()` in Spring Security config |
| `[ ]` | ActuatorEndpointExposedRule | A05 | SPRING_ACTUATOR | `management.endpoints.web.exposure.include=*` in properties — flag `"*"` string literal in `@Value` or config class |
| `[ ]` | HttpsNotEnforcedRule | A05 | INSECURE_CHANNEL | `HttpSecurity` config block that never calls `.requiresChannel()` or `.redirectToHttps()` |
| `[x]` | OpenRedirectRule | A01 | SPRING_UNVALIDATED_REDIRECT | `return "redirect:" + variable` in a `@Controller` method |
| `[x]` | ResponseSplittingRule | A03 | HTTP_RESPONSE_SPLITTING | `response.addHeader(name, variable)` or `response.setHeader(name, variable)` where value is non-literal |
| `[x]` | ELInjectionRule | A03 | EL_INJECTION | `ELProcessor().eval(var)` / `factory.createValueExpression(var, ...)` with non-literal |
| `[x]` | CsrfTokenLeakRule | A01 | CSRF_TOKEN_INTROSPECTION | `model.addAttribute("csrf\|xsrf...", token)` — CSRF token exposed via model |

---

## scanner-dropwizard

Existing: DropwizardMissingAuthRule, InsecureTlsProtocolRule

| Status | Rule | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|----------------|-----------------|
| `[x]` | DropwizardMissingAuthRule | A01 | JAXRS_ENDPOINT | JAX-RS `@GET` etc. without `@RolesAllowed`/`@Auth`/`@DenyAll` |
| `[x]` | InsecureTlsProtocolRule | A02 | SSL_CONTEXT | `setSupportedProtocols("TLSv1.0"\|"SSLv3"...)` |
| `[x]` | InsecureCookieRule | A05 | INSECURE_COOKIE | `NewCookie(name, value)` 2-arg constructor or 8-arg with `secure=false` |
| `[ ]` | JaxRsSqlInjectionRule | A03 | SQL_INJECTION_JPA | Same as core but specifically in `@GET`/`@POST` resource methods with `@QueryParam`-derived values passed to DB calls |
| `[x]` | DropwizardOpenRedirectRule | A01 | UNVALIDATED_REDIRECT | `Response.seeOther(URI(variable))` where variable comes from request param |

---

## scanner-quarkus

Existing: QuarkusMissingAuthRule, QuarkusHardcodedConfigSecretRule

| Status | Rule | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|----------------|-----------------|
| `[x]` | QuarkusMissingAuthRule | A01 | JAXRS_ENDPOINT | JAX-RS without `@RolesAllowed`/`@Authenticated`/`@PermitAll`/`@DenyAll` |
| `[x]` | QuarkusHardcodedConfigSecretRule | A07 | HARD_CODE_PASSWORD | `@ConfigProperty(name="secret", defaultValue="hardcoded")` |
| `[x]` | QuarkusPermitAllSensitiveRule | A01 | JAXRS_ENDPOINT | `@PermitAll` combined with `@DELETE`/`@PUT` — explicitly public write operations |
| `[x]` | QuarkusReflectionUnsafeRule | A08 | OBJECT_DESERIALIZATION | `@RegisterForReflection` on class that implements `Serializable` and overrides `readObject` |
| `[x]` | PanacheRawQueryRule | A03 | SQL_INJECTION_JPA | `PanacheEntity.find(string_with_interpolation)` or `PanacheRepository.find(var)` — Panache raw query with non-literal |
| `[x]` | QuarkusUnsafeHeaderRule | A05 | HTTP_RESPONSE_SPLITTING | `Response.header(name, var)` where value is non-literal — CR/LF enables response splitting |

---

## Phase 2 — Research-backed rules (ready to implement, 2026-06-16)

Research sources: FindSecBugs patterns, real CVEs (listed per rule), competitive gap analysis.
All rules verified absent from free Kotlin tooling ecosystem.
Total after Phase 2: 55 rules across 4 modules.

**Implementation order:** Priority 1 → Priority 2 → Priority 3.
**Properties-file scanning rules** (Priority 2) require a new visitor — see cheat sheet below.

---

### Priority 1 — Kotlin-unique (bytecode tools structurally cannot detect these)

| Status | Rule | Module | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|-------|----------------|-----------------|
| `[ ]` | `CoroutineSecurityContextLossRule` | spring-boot | A01 | — | `suspend fun` annotated with `@PreAuthorize`/`@PostAuthorize` — security context silently dropped. Spring Security issue #10810. `visitNamedFunction` → check `annotationNames()` contains "PreAuthorize"/"PostAuthorize" AND function has `suspend` modifier |
| `[ ]` | `ThymeleafSSTIRule` | spring-boot | A03 | — | `@Controller`/`@GetMapping` method returns `String` built from `@RequestParam`/`@PathVariable` via `+` or interpolation → Thymeleaf SSTI → RCE. CVE 2024 (modzero). `visitNamedFunction` → check `@GetMapping`/`@PostMapping` present + return expression contains string concat with param name |
| `[ ]` | `JacksonUnsafeDeserializationRule` | core | A08 | JACKSON_UNSAFE_DESERIALIZATION | `ObjectMapper().enableDefaultTyping(...)` or `ObjectMapper().activateDefaultTyping(...)` → flag always. Also `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` annotation → `visitCallExpression` callee == "enableDefaultTyping"/"activateDefaultTyping"; also `visitAnnotationEntry` shortName == "JsonTypeInfo" + arg "use" == "Id.CLASS" |
| `[ ]` | `JwtNoneAlgorithmRule` | core | A02 | — | `.signWith(SignatureAlgorithm.NONE, ...)` (jjwt) or `Algorithm.none()` (auth0 java-jwt). `visitCallExpression` callee == "signWith" + first arg contains "NONE"; OR callee == "none" receiver ends with "Algorithm" |
| `[ ]` | `QuarkusJsonBeforeAuthRule` | quarkus | A01 | — | CVE-2023-6267: `@Path` class where `@RolesAllowed` is on methods (not class) + has unannotated body param. `visitClass` → check `@Path` present + class has no class-level `@RolesAllowed`/`@Authenticated` + has method with unannotated request body param |

---

### Priority 2 — Properties-file scanning (new capability, zero competition)

**Note:** These rules need a different detection approach. Options:
- A) Implement as Detekt `FileProcessListener` (scans raw file content)
- B) Implement as `visitStringTemplateExpression` catching `@Value("${...}")` usages
- C) Implement as standalone Gradle task (separate from detekt rules)
- **Recommended:** Option A — `FileProcessListener` gives access to `.properties`/`.yml` raw text

| Status | Rule | Module | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|-------|----------------|-----------------|
| `[ ]` | `InsecureActuatorExposureRule` | spring-boot | A05 | — | `application.properties`/`.yml` contains `management.endpoints.web.exposure.include=*` or `include: "*"`. Real breach: 9TB GPS data via `/actuator/heapdump`. Scan property value == "*" |
| `[ ]` | `QuarkusBuildTimeSecretLeakRule` | quarkus | A05 | — | CVE-2024-2700: `application.properties` contains literal (non-`${...}`) value under key matching `*password*`/`*secret*`/`*token*`/`*key*` in `%prod` profile section |
| `[ ]` | `QuarkusOidcInsecureConfigRule` | quarkus | A07 | — | CVE-2023-1584: `application.properties` contains `quarkus.oidc.token.issuer=any` or is missing `quarkus.oidc.auth-server-url` entirely when `quarkus.oidc.enabled=true` |
| `[ ]` | `InsecureSmtpConfigRule` | spring-boot | A02 | INSECURE_SMTP_SSL | `application.properties` contains `spring.mail.properties.mail.smtp.starttls.enable=false` or `spring.mail.properties.mail.smtp.auth=false` |

---

### Priority 3 — Coverage gaps in existing tools

| Status | Rule | Module | OWASP | FindSecBugs ID | Detection target |
|--------|------|-------|-------|----------------|-----------------|
| `[ ]` | `JwtWeakSecretRule` | core | A02 | HARD_CODE_KEY | `Algorithm.HMAC256(literal)` or `Jwts.builder().signWith(literal)` where literal is a string constant. `visitCallExpression` callee == "HMAC256"/"HMAC384"/"HMAC512"/"signWith" + arg is `KtStringTemplateExpression && !hasInterpolation()` |
| `[ ]` | `WebClientSSRFRule` | spring-boot | A10 | URLCONNECTION_SSRF_FD | `WebClient.create(url)` or `webClient.get().uri(url)` where `url` is a function parameter/non-literal. Companion to existing `SsrfRule` which covers `RestTemplate`/`URL`. `visitCallExpression` callee == "create"/"uri" receiver contains "WebClient" + arg not literal |
| `[ ]` | `SpringDataMongoInjectionRule` | spring-boot | A03 | SQL_INJECTION_JPA | `Criteria.where(field).is(userInput)` where either arg is non-literal. NoSQL injection. `visitCallExpression` callee == "where"/"is" on Criteria chain + arg non-literal |
| `[ ]` | `DropwizardSelfValidatingELRule` | dropwizard | A03 | EL_INJECTION | CVE-2020-5245 + CVE-2020-11002: `@SelfValidating` class + `buildConstraintViolationWithTemplate(nonLiteral)`. `visitCallExpression` callee == "buildConstraintViolationWithTemplate" + arg non-literal |
| `[ ]` | `MissingHttpsRedirectRule` | spring-boot | A02 | — | `SecurityFilterChain` bean (function annotated `@Bean` returning `SecurityFilterChain`) without `requiresChannel` call in body. Absence detection — `visitNamedFunction` → check `@Bean` + return type + scan body for missing `requiresChannel`/`requiresSecure` |
| `[ ]` | `InsecureRedisConnectionRule` | spring-boot | A02 | UNENCRYPTED_SOCKET | `RedisStandaloneConfiguration(...)` or `LettuceConnectionFactory(...)` without `.useSsl(true)` or `RedisSSLContext`. `visitCallExpression` callee == "RedisStandaloneConfiguration"/"LettuceConnectionFactory" → check no chained `useSsl(true)` in parent |
| `[ ]` | `UnsafeCryptoPaddingOracleRule` | core | A02 | PADDING_ORACLE | `Cipher.getInstance("AES/CBC/PKCS5Padding")` without `Mac.getInstance("HmacSHA256")` in same scope. Flag `AES/CBC/PKCS5Padding` always (safe alternative is GCM). `visitCallExpression` callee == "getInstance" + arg literal == "AES/CBC/PKCS5Padding" |
| `[ ]` | `RegexDenialOfServiceRule` | core | A06 | REDOS | `Regex(pattern)` or `"...".toRegex()` where pattern literal contains catastrophic backtracking: `(a+)+`, `([a-z]+)*`, `(a\|aa)+`. `visitCallExpression` callee == "Regex"/"toRegex" + literal arg matches ReDoS Regex patterns |
| `[ ]` | `XmlMapperUnsafeRule` | core | A08 | JACKSON_UNSAFE_DESERIALIZATION | `XmlMapper()` constructor call without subsequent `configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)`. `visitCallExpression` callee == "XmlMapper" (constructor) → flag always with "disable DTD / set FAIL_ON_UNKNOWN_PROPERTIES" message |
| `[ ]` | `InsecurePasswordStorageRule` | core | A02 | WEAK_MESSAGE_DIGEST_MD5 | `MessageDigest.getInstance("SHA-256")` / `DigestUtils.sha256Hex(arg)` used for password hashing (detected by proximity to "password"/"passwd" variable names). Distinct from `WeakHashAlgorithmRule` which catches MD5/SHA1 — this catches SHA-256 WITHOUT salt |
| `[ ]` | `DropwizardUnencryptedJwtSecretRule` | dropwizard | A02 | HARD_CODE_KEY | `JwtAuthFilter.Builder<>().setSecretProvider(literal)` where literal is string. `visitCallExpression` callee == "setSecretProvider" + arg is literal |

---

## Phase 2 detection cheat sheet (new patterns)

### Properties-file scanning — FileProcessListener approach
```kotlin
// Implement FileProcessListener (NOT a Rule subclass)
// Register in: META-INF/services/io.gitlab.arturbosch.detekt.api.FileProcessListener
class InsecureActuatorExposureListener : FileProcessListener {
    override fun onProcess(file: KtFile, bindingContext: BindingContext) { }
    override fun onProcessComplete(
        file: KtFile,
        findings: Map<String, List<Finding>>,
        bindingContext: BindingContext
    ) { }
}
// Alternative: scan non-Kotlin files in a custom Gradle task
```

### Check `suspend` modifier on a function
```kotlin
import org.jetbrains.kotlin.lexer.KtTokens
function.hasModifier(KtTokens.SUSPEND_KEYWORD)
```

### Detect absence of a call in function body
```kotlin
val bodyText = function.bodyExpression?.text ?: return
if ("requiresChannel" !in bodyText) reportAt(function, "...")
```

### visitAnnotationEntry (e.g. @JsonTypeInfo)
```kotlin
override fun visitAnnotationEntry(entry: KtAnnotationEntry) {
    super.visitAnnotationEntry(entry)
    if (entry.shortName?.asString() != "JsonTypeInfo") return
    // entry.literalArg("use") → "Id.CLASS" etc.
}
```

### ReDoS literal pattern check
```kotlin
val reDoSPatterns = listOf(
    Regex("""\(.*\+\)\+"""),         // (a+)+
    Regex("""\(\[.*]\+\)\*"""),      // ([a-z]+)*
    Regex("""\(.*\|.*\)\+"""),       // (a|aa)+
)
fun String.hasReDoSPattern() = reDoSPatterns.any { it.containsMatchIn(this) }
```

---

## Detection patterns cheat sheet (pre-researched)

### Command injection
```
visitCallExpression → callee == "exec" && receiver is "Runtime" → check args are not all literals
visitCallExpression → callee == "ProcessBuilder" → check constructor args are not all literals
```
Patterns to add to DetectionPatterns: `COMMAND_EXEC_METHODS = setOf("exec")`, `PROCESS_BUILDER = "ProcessBuilder"`

### XXE
```
visitCallExpression → callee == "newInstance" && receiver text contains "DocumentBuilderFactory"|"SAXParserFactory"|"XMLInputFactory"
→ check if parent chain contains setFeature("disallow-doctype-decl", true) — hard to do statically
→ simpler: flag any DocumentBuilderFactory.newInstance() call (false positives OK, require explicit fix)
```
Patterns: `XXE_FACTORY_CLASSES = setOf("DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "TransformerFactory")`

### Insecure deserialization
```
visitCallExpression → callee == "ObjectInputStream" (constructor) → flag always
```
Patterns: `UNSAFE_DESERIALIZERS = setOf("ObjectInputStream", "XMLDecoder")`

### SpEL injection
```
visitCallExpression → callee == "parseExpression" → check arg is not literal KtStringTemplateExpression
```
Patterns: `SPEL_PARSER_METHODS = setOf("parseExpression", "parseRaw")`

### Insecure password encoder
```
visitCallExpression → callee == "getInstance" && receiver text == "NoOpPasswordEncoder" → flag
visitCallExpression → callee == "Md5PasswordEncoder"|"ShaPasswordEncoder" → flag constructor
```
Patterns: `WEAK_PASSWORD_ENCODERS = setOf("NoOpPasswordEncoder", "Md5PasswordEncoder", "ShaPasswordEncoder", "LdapShaPasswordEncoder")`

### Weak hash
```
visitCallExpression → callee == "getInstance" → first arg is literal matching MD5|SHA-1|SHA1
```
Patterns: `WEAK_HASH_ALGORITHMS = listOf(Regex("^MD5$"), Regex("^SHA-?1$", IGNORE_CASE))`

### Trust all certs (null trust manager)
```
visitClassBody → anonymous object implementing X509TrustManager → check if checkServerTrusted body is empty/returns Unit
```
Patterns: `TRUST_MANAGER_INTERFACE = "X509TrustManager"`, `TRUST_CHECK_METHODS = setOf("checkClientTrusted", "checkServerTrusted")`
