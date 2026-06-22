package com.example

import java.io.File
import java.io.ObjectInputStream
import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.naming.InitialContext
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathFactory

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

fun hashPassword(password: String): ByteArray {
    // VULNERABLE: MD5 is broken [WeakHashAlgorithm, CWE-327]
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(password.toByteArray())
}

fun encryptDataEcb(data: ByteArray, key: javax.crypto.SecretKey): ByteArray {
    // VULNERABLE: ECB mode leaks patterns [WeakCipherMode, CWE-327]
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return cipher.doFinal(data)
}

fun encryptDataCbc(data: ByteArray, key: javax.crypto.SecretKey): ByteArray {
    // VULNERABLE: CBC/PKCS5Padding without MAC — padding oracle [UnsafeCryptoPaddingOracle, CWE-649]
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return cipher.doFinal(data)
}

fun buildHardcodedIv(): IvParameterSpec {
    // VULNERABLE: static IV — same ciphertext for same plaintext [HardcodedIv, CWE-329]
    return IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
}

fun generateWeakRsaKey() {
    // VULNERABLE: RSA-1024 is considered broken [WeakRsaKey, CWE-326]
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(1024)
}

class InsecureTrustManager : javax.net.ssl.X509TrustManager {
    // VULNERABLE: empty body accepts all certificates [TrustAllCerts, CWE-295]
    override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
}

fun signWithNoneAlgorithm() {
    // VULNERABLE: JWT none algorithm disables signature verification [JwtNoneAlgorithm, CWE-347]
    com.auth0.jwt.JWT.require(com.auth0.jwt.algorithms.Algorithm.none()).build()
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

fun findUser(conn: java.sql.Connection, username: String) {
    // VULNERABLE: SQL injection via string concatenation [SqlInjection, CWE-89]
    val query = "SELECT * FROM users WHERE username = '" + username + "'"
    conn.createStatement().executeQuery(query)
}

fun readFile(userInput: String): String {
    // VULNERABLE: path traversal [PathTraversal, CWE-22]
    return File(userInput).readText()
}

fun runCommand(userInput: String) {
    // VULNERABLE: command injection — exec with interpolated argument [CommandInjection, CWE-78]
    Runtime.getRuntime().exec("ls $userInput")
}

fun lookupJndi(name: String) {
    // VULNERABLE: JNDI injection — dynamic name may be ldap:// remote URL [JndiInjection, CWE-74]
    val ctx = InitialContext()
    ctx.lookup(name)
}

fun searchLdap(username: String) {
    // VULNERABLE: LDAP injection — interpolated filter [LdapInjection, CWE-90]
    val env = java.util.Hashtable<String, String>()
    val ctx = javax.naming.directory.InitialDirContext(env)
    ctx.search("ou=users", "(uid=$username)", javax.naming.directory.SearchControls())
}

fun queryXpath(name: String) {
    // VULNERABLE: XPath injection — interpolated expression [XpathInjection, CWE-643]
    val xpath = XPathFactory.newInstance().newXPath()
    val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument()
    xpath.evaluate("//user[@name='$name']", doc, XPathConstants.NODE)
}

fun loadClassDynamic(className: String) {
    // VULNERABLE: reflection injection — attacker-controlled class loading [ReflectionInjection, CWE-470]
    Class.forName(className)
}

fun parseXmlUnsafe() {
    // VULNERABLE: external entities enabled by default [XxeInjection, CWE-611]
    DocumentBuilderFactory.newInstance()
}

fun runGroovyScript(userScript: String) {
    // VULNERABLE: Groovy script injection — user-controlled script [GroovyScriptInjection, CWE-94]
    val shell = groovy.lang.GroovyShell()
    shell.evaluate(userScript)
}

// ── A06 Vulnerable Components / ReDoS ─────────────────────────────────────────

fun validateEmailPattern(input: String): Boolean {
    // VULNERABLE: catastrophic backtracking [RegexDenialOfService, CWE-400]
    return Regex("(a+)+").matches(input)
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class DatabaseConfig {
    // VULNERABLE: hardcoded credentials [HardcodedCredentials, CWE-798]
    val dbPassword = "superSecretProd2024!"
    val apiKey = "sk-live-abc123def456ghi789"
    // VULNERABLE: hardcoded AWS access key [HardcodedAwsCredentials, CWE-798]
    val awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
}

fun generateSessionToken(): Int {
    // VULNERABLE: predictable randomness [InsecureRandom, CWE-330]
    return java.util.Random().nextInt(1_000_000)
}

// ── A08 Software and Data Integrity ──────────────────────────────────────────

fun deserializeObject(inputStream: java.io.InputStream): Any {
    // VULNERABLE: unsafe Java deserialization [InsecureDeserialization, CWE-502]
    return ObjectInputStream(inputStream).readObject()
}

fun createXmlMapper(): com.fasterxml.jackson.dataformat.xml.XmlMapper {
    // VULNERABLE: XmlMapper with unsafe Jackson defaults [XmlMapperUnsafe, CWE-502]
    return com.fasterxml.jackson.dataformat.xml.XmlMapper()
}

@kotlinx.serialization.Serializable
data class UserCredentials(
    val username: String,
    // VULNERABLE: sensitive field serialized without @Transient [KotlinxSerializationSensitiveField, CWE-312]
    val password: String,
    val secret: String,
)

// ── A09 Security Logging and Monitoring ──────────────────────────────────────

fun authenticate(username: String, password: String) {
    val logger = org.slf4j.LoggerFactory.getLogger("Auth")
    // VULNERABLE: credentials in log output [SensitiveDataLogging, CWE-532]
    logger.info("Login attempt: user=$username password=$password")
}

// ── A10 Server-Side Request Forgery ──────────────────────────────────────────

fun fetchExternalResource(userSuppliedUrl: String): String {
    // VULNERABLE: SSRF — user controls URL [SsrfRule, CWE-918]
    val url = java.net.URL(userSuppliedUrl)
    return url.openStream().bufferedReader().readText()
}

// ── A02 New core rules ────────────────────────────────────────────────────────

fun buildAesCipherWithLiteralKey(): javax.crypto.Cipher {
    // VULNERABLE: AES key is a hardcoded byte array [HardcodedAesKey, CWE-321]
    val key = javax.crypto.spec.SecretKeySpec(
        byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10), "AES"
    )
    return javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").also { it.init(javax.crypto.Cipher.ENCRYPT_MODE, key) }
}

fun buildAesCipherWithStringKey(): javax.crypto.Cipher {
    // VULNERABLE: AES key is a hardcoded string literal [HardcodedAesKey, CWE-321]
    val key = javax.crypto.spec.SecretKeySpec("my-secret-key!!!".toByteArray(), "AES")
    return javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").also { it.init(javax.crypto.Cipher.ENCRYPT_MODE, key) }
}

fun disableSslHostnameVerification(conn: javax.net.ssl.HttpsURLConnection) {
    // VULNERABLE: HostnameVerifier always returns true [TrustAllHostnames, CWE-297]
    conn.setHostnameVerifier { _, _ -> true }
}

// VULNERABLE: RSA private key PEM material in source [HardcodedPrivateKey, CWE-321]
val rsaPrivateKeyPem = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4vI7V+...
    -----END RSA PRIVATE KEY-----
""".trimIndent()

fun buildInsecureRng(): java.security.SecureRandom {
    // VULNERABLE: SecureRandom seeded with constant [InsecureRandomSeed, CWE-335]
    return java.security.SecureRandom(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))
}
