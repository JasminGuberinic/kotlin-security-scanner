package com.jasmin.security.detekt.core

/**
 * Single source of truth for all vulnerability detection patterns.
 *
 * Grouping by OWASP category makes it easy to find, extend, or
 * tune a pattern without touching the rule logic itself.
 * Community contributions: add new patterns here first, then wire
 * them into the relevant rule.
 */
object DetectionPatterns {

    // ── A02 Cryptographic Failures ────────────────────────────────────────────

    val WEAK_HASH_ALGORITHMS = listOf(
        Regex("""^MD5$""", RegexOption.IGNORE_CASE),
        Regex("""^SHA-?1$""", RegexOption.IGNORE_CASE),
    )

    val TRUST_CHECK_METHODS = setOf("checkClientTrusted", "checkServerTrusted")

    const val IV_CONSTRUCTOR = "IvParameterSpec"
    const val BYTE_ARRAY_LITERAL = "byteArrayOf"

    val WEAK_PASSWORD_ENCODERS = setOf(
        "NoOpPasswordEncoder",
        "Md5PasswordEncoder",
        "ShaPasswordEncoder",
        "LdapShaPasswordEncoder",
        "MessageDigestPasswordEncoder",
    )

    val WEAK_CIPHER_ALGORITHMS = listOf(
        Regex("""/ECB/""", RegexOption.IGNORE_CASE),
        Regex("""^DES[^e]""", RegexOption.IGNORE_CASE),
        Regex("""^DESede""", RegexOption.IGNORE_CASE),
        Regex("""^RC2""", RegexOption.IGNORE_CASE),
        Regex("""^RC4""", RegexOption.IGNORE_CASE),
        Regex("""^Blowfish""", RegexOption.IGNORE_CASE),
        Regex("""NullCipher""", RegexOption.IGNORE_CASE),
    )

    // ── A03 Injection ─────────────────────────────────────────────────────────

    val COMMAND_EXEC_METHODS = setOf("exec")
    const val PROCESS_BUILDER_CLASS = "ProcessBuilder"

    val LDAP_OPERATION_METHODS = setOf("search", "bind", "lookup", "modifyAttributes", "rename")

    val XPATH_EXPRESSION_METHODS = setOf("evaluate", "selectNodes", "selectSingleNode")

    val JNDI_METHODS = setOf("lookup", "rebind")

    const val CLASS_FOR_NAME_METHOD = "forName"
    const val CLASS_FOR_NAME_RECEIVER = "Class"

    const val KEY_GEN_INIT_METHOD = "initialize"

    val SCRIPT_EVAL_METHODS = setOf("evaluate", "eval")

    val EL_EVAL_METHODS = setOf("eval", "createValueExpression")

    val CSRF_TOKEN_KEYWORDS = setOf("csrf", "xsrf")

    val HTTP_HEADER_SETTER_METHODS = setOf("addHeader", "setHeader")

    const val REDIRECT_PREFIX = "redirect:"

    val PANACHE_QUERY_METHODS = setOf("find", "list", "stream", "count", "delete", "update")

    val JAXRS_WRITE_METHODS = setOf("DELETE", "PUT", "PATCH")

    const val SPRING_REQUEST_BODY_ANNOTATION = "RequestBody"
    val ENTITY_ANNOTATIONS = setOf("Entity", "Document", "Table")

    val XXE_FACTORY_CLASSES = setOf(
        "DocumentBuilderFactory",
        "SAXParserFactory",
        "XMLInputFactory",
        "TransformerFactory",
        "SchemaFactory",
    )

    // ── A08 Software and Data Integrity ───────────────────────────────────────

    val UNSAFE_DESERIALIZERS = setOf(
        "ObjectInputStream",
        "XMLDecoder",
    )

    // ── A03 (continued) ───────────────────────────────────────────────────────

    val SQL_KEYWORDS = listOf("SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN")

    val FILE_CONSTRUCTORS = setOf(
        "File",
        "FileInputStream",
        "FileOutputStream",
        "FileReader",
        "FileWriter",
    )

    val PATH_METHODS = setOf("get", "of", "resolve")

    val SSRF_CONSTRUCTORS = setOf("URL", "URI")

    // ── A05 Security Misconfiguration ─────────────────────────────────────────

    val CSRF_DISABLE_CALLEE_NAMES = setOf("csrf", "disable")

    val CORS_WILDCARD = setOf("*", "allowedOrigins")

    // ── A07 Authentication Failures ───────────────────────────────────────────

    val CREDENTIAL_VARIABLE_KEYWORDS = setOf(
        "password", "passwd", "pwd", "secret", "apikey", "api_key",
        "token", "auth", "credential", "private_key", "privatekey",
        "access_key", "accesskey", "client_secret", "clientsecret"
    )

    val SAFE_CREDENTIAL_PLACEHOLDERS = listOf(
        Regex("""^\$\{.*}$"""),
        Regex("""^#\{.*}$"""),
        Regex("""^\*+$"""),
        Regex("""^$"""),
        Regex("""^\s+$"""),
        Regex("changeme", RegexOption.IGNORE_CASE),
        Regex("placeholder", RegexOption.IGNORE_CASE),
        Regex("your[-_]?.*here", RegexOption.IGNORE_CASE),
    )

    val INSECURE_RANDOM_CLASSES = setOf("Random", "ThreadLocalRandom")

    // ── A09 Logging Failures ──────────────────────────────────────────────────

    val LOG_METHOD_NAMES = setOf("trace", "debug", "info", "warn", "error", "log")

    val SENSITIVE_LOG_KEYWORDS = setOf(
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "credential", "privatekey", "private_key", "accesskey", "access_key",
        "clientsecret", "client_secret", "authorization", "bearer"
    )

    // ── A03 Spring SpEL Injection ─────────────────────────────────────────────

    val SPEL_PARSER_METHODS = setOf("parseExpression", "parseRaw")

    // ── A01 Broken Access Control ─────────────────────────────────────────────

    val SPRING_ENDPOINT_ANNOTATIONS = setOf(
        "RequestMapping",
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
    )

    val SPRING_SECURITY_ANNOTATIONS = setOf(
        "PreAuthorize",
        "PostAuthorize",
        "Secured",
        "RolesAllowed",
    )

    // ── A01 Quarkus / MicroProfile Access Control ─────────────────────────────

    // Quarkus uses the standard JAX-RS HTTP method annotations (same as Dropwizard)
    // but adds @Authenticated from io.quarkus.security as an alternative to @RolesAllowed.
    val QUARKUS_AUTH_ANNOTATIONS = setOf(
        "RolesAllowed",
        "DenyAll",
        "PermitAll",
        "Authenticated", // io.quarkus.security.Authenticated
    )

    // ── A01 Dropwizard / JAX-RS Access Control ────────────────────────────────

    val JAXRS_HTTP_METHODS = setOf(
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    )

    val JAXRS_AUTH_ANNOTATIONS = setOf(
        "RolesAllowed",
        "DenyAll",
        "Auth",
        "PermitAll",
    )

    // ── A01 Dropwizard open redirect ─────────────────────────────────────────

    val JAXRS_REDIRECT_METHODS = setOf("seeOther", "temporaryRedirect")

    // ── A05 Dropwizard insecure cookie ────────────────────────────────────────

    const val NEW_COOKIE = "NewCookie"

    // ── A08 Quarkus reflection ────────────────────────────────────────────────

    const val REGISTER_FOR_REFLECTION = "RegisterForReflection"

    // ── A02 Dropwizard insecure TLS ───────────────────────────────────────────

    val INSECURE_TLS_PROTOCOLS = listOf(
        Regex("""TLSv1$""", RegexOption.IGNORE_CASE),
        Regex("""TLSv1\.0""", RegexOption.IGNORE_CASE),
        Regex("""TLSv1\.1""", RegexOption.IGNORE_CASE),
        Regex("""SSLv2""", RegexOption.IGNORE_CASE),
        Regex("""SSLv3""", RegexOption.IGNORE_CASE),
    )

    val TLS_SETTER_NAMES = setOf(
        "setSupportedProtocols",
        "setEnabledProtocols",
        "setSslProtocol",
    )

    // ── A02 JWT ───────────────────────────────────────────────────────────────

    const val JWT_SIGN_WITH_METHOD = "signWith"
    // Auth0 JWT (HMAC256/384/512), Nimbus JOSE JWT (MACSigner/MACVerifier), JJWT v1 key-builder (hmacShaKeyFor)
    val JWT_HMAC_METHODS = setOf("HMAC256", "HMAC384", "HMAC512", "MACSigner", "MACVerifier", "hmacShaKeyFor")
    const val JWT_NONE_METHOD = "none"
    const val JWT_NONE_ALGORITHM_TEXT = "NONE"
    const val AUTH0_ALGORITHM_CLASS = "Algorithm"

    // ── A02 Cipher ────────────────────────────────────────────────────────────

    const val UNSAFE_CBC_PADDING = "AES/CBC/PKCS5Padding"

    // ── A08 Jackson ───────────────────────────────────────────────────────────

    val JACKSON_UNSAFE_TYPING_METHODS = setOf("enableDefaultTyping", "activateDefaultTyping")
    const val JACKSON_TYPE_INFO_ANNOTATION = "JsonTypeInfo"
    const val XML_MAPPER_CLASS = "XmlMapper"

    // ── A06 ReDoS ─────────────────────────────────────────────────────────────

    val REGEX_CONSTRUCTORS = setOf("Regex", "toRegex")
    val REDOS_PATTERNS = listOf(
        Regex("""\(.*\+\)\+"""),
        Regex("""\(\[.*\]\+\)\*"""),
        Regex("""\(.*\|.*\)\+"""),
        Regex("""\(.*\+\)\*"""),
    )

    // ── A10 WebClient SSRF ────────────────────────────────────────────────────

    const val WEB_CLIENT_CREATE = "create"
    const val WEB_CLIENT_CLASS = "WebClient"

    // ── A02 Redis TLS ─────────────────────────────────────────────────────────

    val REDIS_CONNECTION_CONSTRUCTORS = setOf(
        "RedisStandaloneConfiguration",
        "LettuceConnectionFactory",
        "JedisConnectionFactory",
        "RedisSentinelConfiguration",
        "RedisClusterConfiguration",
    )

    // ── A03 MongoDB ───────────────────────────────────────────────────────────

    const val MONGO_CRITERIA_WHERE = "where"
    const val MONGO_CRITERIA_CLASS = "Criteria"

    // ── A03 Dropwizard constraint EL ──────────────────────────────────────────

    const val DW_CONSTRAINT_VIOLATION_TEMPLATE = "buildConstraintViolationWithTemplate"

    // ── A02 Dropwizard JWT ────────────────────────────────────────────────────

    const val DW_JWT_SECRET_PROVIDER = "setSecretProvider"

    // ── A02 Password Storage ──────────────────────────────────────────────────

    // Algorithms that are cryptographically weak OR lack work-factor/salting for passwords
    val PASSWORD_WEAK_HASH_ALGORITHMS = setOf("MD5", "SHA", "SHA-1", "SHA-256", "SHA-384", "SHA-512")
    val PASSWORD_FUNCTION_KEYWORDS = setOf("password", "passwd", "pwd", "credential")
    const val MESSAGE_DIGEST_GET_INSTANCE = "getInstance"
    const val MESSAGE_DIGEST_CLASS = "MessageDigest"
    val DIGEST_UTILS_METHODS = setOf("md5Hex", "sha1Hex", "sha256Hex", "sha384Hex", "sha512Hex")
    const val DIGEST_UTILS_CLASS = "DigestUtils"

    // ── A03 Thymeleaf SSTI ────────────────────────────────────────────────────

    const val THYMELEAF_PROCESS_METHOD = "process"
    val THYMELEAF_ENGINE_RECEIVERS = setOf("templateengine", "thymeleaf")

    // ── A02 BCrypt ────────────────────────────────────────────────────────────

    const val BCRYPT_ENCODER_CLASS = "BCryptPasswordEncoder"
    const val BCRYPT_MIN_ROUNDS = 10

    // ── A02 RSA key size ──────────────────────────────────────────────────────

    const val RSA_MIN_KEY_SIZE = 2048

    // ── A02 JWT Expiration ────────────────────────────────────────────────────

    const val JWT_COMPACT_METHOD = "compact"

    // ── A05 Exception Details Exposure ────────────────────────────────────────

    const val EXCEPTION_HANDLER_ANNOTATION = "ExceptionHandler"
    val EXCEPTION_DETAIL_PATTERNS = listOf(
        "e.message",
        "ex.message",
        "exception.message",
        "err.message",
        "t.message",
        "throwable.message",
        ".localizedMessage",
        "printStackTrace",
        ".stackTraceToString",
    )

    // ── A05 HTTP Method Override ──────────────────────────────────────────────

    const val HTTP_METHOD_OVERRIDE_FILTER = "HiddenHttpMethodFilter"

    // ── A08 Kotlinx Serialization ─────────────────────────────────────────────

    const val KOTLINX_SERIALIZABLE_ANNOTATION = "Serializable"
    const val KOTLINX_TRANSIENT_ANNOTATION = "Transient"
    val SERIALIZATION_SENSITIVE_FIELDS = setOf(
        "password",
        "passwd",
        "pwd",
        "secret",
        "privatekey",
        "private_key",
        "clientsecret",
        "client_secret",
    )

    // ── A07 Hardcoded Cloud Credentials ──────────────────────────────────────

    val AWS_ACCESS_KEY_PATTERN = Regex("""(AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}""")

    // ── A03 Quarkus Bean Validation ───────────────────────────────────────────

    val JAXRS_ENTITY_METHODS = setOf("POST", "PUT")
    val JAXRS_PARAM_ANNOTATIONS = setOf(
        "PathParam",
        "QueryParam",
        "HeaderParam",
        "FormParam",
        "CookieParam",
        "Context",
        "BeanParam",
        "MatrixParam",
    )

    // ── A01 Admin / privileged paths ─────────────────────────────────────────

    val ADMIN_PATHS = listOf(
        "/admin",
        "/actuator",
        "/management",
        "/console",
        "/h2-console",
    )

    // ── A03 JPA EntityManager ─────────────────────────────────────────────────

    val ENTITY_MANAGER_QUERY_METHODS = setOf("createQuery", "createNativeQuery")

    // ── A10 RestTemplate SSRF ─────────────────────────────────────────────────

    val REST_TEMPLATE_METHODS = setOf(
        "getForObject",
        "getForEntity",
        "postForObject",
        "postForEntity",
        "exchange",
    )

    // ── Ktor ──────────────────────────────────────────────────────────────────

    const val KTOR_ROUTING = "routing"
    const val KTOR_INSTALL = "install"
    const val KTOR_SESSIONS_FEATURE = "Sessions"
    const val KTOR_CORS_FEATURE = "CORS"
    const val KTOR_ANY_HOST = "anyHost()"
    const val KTOR_RESPOND_REDIRECT = "respondRedirect"
    const val KTOR_RESPOND_TEXT = "respondText"
    const val KTOR_BASIC_AUTH = "basic"
    const val KTOR_COOKIE_CLASS = "Cookie"
    val KTOR_SESSION_TRANSFORM_CLASSES = setOf(
        "SessionTransportTransformerEncrypt",
        "SessionTransportTransformerMessageAuthentication",
    )

    // ── Micronaut ─────────────────────────────────────────────────────────────

    val MICRONAUT_HTTP_METHODS = setOf("Get", "Post", "Put", "Delete", "Patch", "Options", "Head")
    val MICRONAUT_AUTH_ANNOTATIONS = setOf("Secured")
}
