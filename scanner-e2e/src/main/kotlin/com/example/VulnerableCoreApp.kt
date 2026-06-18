package com.example

import java.io.File
import java.io.ObjectInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

fun hashPassword(password: String): ByteArray {
    // VULNERABLE: MD5 is cryptographically broken [CWE-327]
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(password.toByteArray())
}

fun encryptData(data: ByteArray, key: javax.crypto.SecretKey): ByteArray {
    // VULNERABLE: ECB mode leaks patterns [CWE-327]
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return cipher.doFinal(data)
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

fun findUser(conn: java.sql.Connection, username: String) {
    // VULNERABLE: SQL injection via string concatenation [CWE-89]
    val query = "SELECT * FROM users WHERE username = '" + username + "'"
    conn.createStatement().executeQuery(query)
}

fun readFile(userInput: String): String {
    // VULNERABLE: path traversal — user controls file path [CWE-22]
    return File(userInput).readText()
}

fun runCommand(userInput: String) {
    // VULNERABLE: command injection [CWE-78]
    Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", userInput))
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class DatabaseConfig {
    // VULNERABLE: hardcoded production credentials [CWE-798]
    val dbPassword = "super${'$'}ecretProd2024!"
    val apiKey = "sk-live-abc123def456ghi789"
}

fun generateSessionToken(): Int {
    // VULNERABLE: predictable randomness — not cryptographically secure [CWE-330]
    return java.util.Random().nextInt(1_000_000)
}

// ── A08 Software and Data Integrity ──────────────────────────────────────────

fun deserializeObject(inputStream: java.io.InputStream): Any {
    // VULNERABLE: unsafe deserialization of untrusted data [CWE-502]
    return ObjectInputStream(inputStream).readObject()
}

// ── A09 Security Logging and Monitoring ──────────────────────────────────────

fun authenticate(username: String, password: String) {
    val logger = org.slf4j.LoggerFactory.getLogger("Auth")
    // VULNERABLE: logging credentials [CWE-532]
    logger.info("Login attempt: user=${'$'}username password=${'$'}password")
}

// ── A10 Server-Side Request Forgery ──────────────────────────────────────────

fun fetchExternalResource(userSuppliedUrl: String): String {
    // VULNERABLE: SSRF — user controls the URL [CWE-918]
    val url = java.net.URL(userSuppliedUrl)
    return url.openStream().bufferedReader().readText()
}
