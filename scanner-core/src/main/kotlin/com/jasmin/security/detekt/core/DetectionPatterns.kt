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
}
