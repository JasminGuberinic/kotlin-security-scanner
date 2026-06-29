package com.example

// Intentionally vulnerable Vert.x code — exercises every scanner-vertx rule end to end.

// VULNERABLE: TLS verification disabled [VertxTrustAllCerts, CWE-295]
fun vertxClient() =
    io.vertx.core.http.HttpClientOptions().setSsl(true).setTrustAll(true)

fun vertxWebClient() =
    io.vertx.ext.web.client.WebClientOptions().setVerifyHost(false)

// VULNERABLE: CORS allows any origin [VertxCorsWildcard, CWE-942]
fun vertxCors(router: io.vertx.ext.web.Router) =
    router.route().handler(io.vertx.ext.web.handler.CorsHandler.create(".*"))

// VULNERABLE: unbounded request body [VertxBodyHandlerNoLimit, CWE-400]
fun vertxBody(router: io.vertx.ext.web.Router) =
    router.route().handler(io.vertx.ext.web.handler.BodyHandler.create())

// VULNERABLE: event-bus bridge exposes every address [VertxEventBusBridgeOpen, CWE-862]
fun vertxBridge() =
    io.vertx.ext.web.handler.sockjs.SockJSBridgeOptions()
        .addInboundPermitted(io.vertx.ext.bridge.PermittedOptions().setAddressRegex(".*"))

// VULNERABLE: cookie sent over plain HTTP [VertxInsecureCookie, CWE-614]
fun vertxCookie(id: String) =
    io.vertx.core.http.Cookie.cookie("session", id).setSecure(false)

// VULNERABLE: cookie readable by JavaScript [VertxCookieNoHttpOnly, CWE-1004]
fun vertxCookieHttpOnly(id: String) =
    io.vertx.core.http.Cookie.cookie("session", id).setHttpOnly(false)

// VULNERABLE: session cookie over plain HTTP [VertxSessionCookieInsecure, CWE-614]
fun vertxSession(store: Any) =
    io.vertx.ext.web.handler.SessionHandler.create(store).setCookieSecureFlag(false)

// VULNERABLE: browsable file index [VertxStaticHandlerDirectoryListing, CWE-548]
fun vertxStaticListing() =
    io.vertx.ext.web.handler.StaticHandler.create("webroot").setDirectoryListing(true)

// VULNERABLE: serves the filesystem root [VertxStaticHandlerRootFs, CWE-22]
fun vertxStaticRoot() =
    io.vertx.ext.web.handler.StaticHandler.create("/")

// VULNERABLE: JWT 'none' algorithm [VertxJwtNoneAlgorithm, CWE-347]
fun vertxJwtNone() =
    io.vertx.ext.auth.PubSecKeyOptions().setAlgorithm("none")

// VULNERABLE: hardcoded JWT signing secret [VertxHardcodedJwtSecret, CWE-798]
fun vertxJwtSecret() =
    io.vertx.ext.auth.PubSecKeyOptions().setAlgorithm("HS256").setBuffer("hardcoded-jwt-secret-value")
