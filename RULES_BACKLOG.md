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
| `[x]` | TrustAllCertsRule | A02 | WEAK_TRUST_MANAGER | anonymous `X509TrustManager` with empty `checkClientTrusted`/`checkServerTrusted` |
| `[x]` | HardcodedIvRule | A02 | STATIC_IV | `IvParameterSpec(byteArrayOf(...))` with literal byte array — IV must be random |

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
| `[ ]` | ActuatorEndpointExposedRule | A05 | SPRING_ACTUATOR | `management.endpoints.web.exposure.include=*` in properties — flag `"*"` string literal in `@Value` or config class |
| `[ ]` | HttpsNotEnforcedRule | A05 | INSECURE_CHANNEL | `HttpSecurity` config block that never calls `.requiresChannel()` or `.redirectToHttps()` |
| `[x]` | OpenRedirectRule | A01 | SPRING_UNVALIDATED_REDIRECT | `return "redirect:" + variable` in a `@Controller` method |
| `[x]` | ResponseSplittingRule | A03 | HTTP_RESPONSE_SPLITTING | `response.addHeader(name, variable)` or `response.setHeader(name, variable)` where value is non-literal |

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

---

## Priority order for next session

1. `JaxRsSqlInjectionRule` (dropwizard) — A03, SQL injection in JAX-RS @QueryParam methods
2. `ActuatorEndpointExposedRule` (spring-boot) — A05, Spring Boot actuator exposure
3. `HttpsNotEnforcedRule` (spring-boot) — A05, cleartext HTTP allowed in SecurityFilterChain

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
