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
