'use strict';

if (ObjC.available) {
    console.log("[*] N0tSoNormal Custom Script: Starting advanced iOS SSL pinning bypass");

    // Hook SecTrustEvaluate
    try {
        const secTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");
        Interceptor.attach(secTrustEvaluate, {
            onEnter: function (args) {
                console.log("[Bypass] SecTrustEvaluate()");
            },
            onLeave: function (retval) {
                retval.replace(1); // TRUE
                console.log("[Bypass] SecTrustEvaluate result forced");
            }
        });
    } catch (err) {
        console.log("[!] SecTrustEvaluate error: " + err);
    }

    // Hook SecTrustEvaluateWithError
    try {
        const secTrustEvaluateWithError = Module.findExportByName(null, "SecTrustEvaluateWithError");
        Interceptor.attach(secTrustEvaluateWithError, {
            onEnter: function (args) {
                console.log("[Bypass] SecTrustEvaluateWithError()");
            },
            onLeave: function (retval) {
                retval.replace(1); // TRUE
                console.log("[Bypass] SecTrustEvaluateWithError result forced");
            }
        });
    } catch (err) {
        console.log("[!] SecTrustEvaluateWithError error: " + err);
    }

    // Hook NSURLSessionDelegate
    try {
        const hookNSURLSession = ObjC.classes.NSURLSessionDelegate;
        const method = "- URLSession:didReceiveChallenge:completionHandler:";
        for (const clsName in ObjC.classes) {
            const cls = ObjC.classes[clsName];
            if (cls && cls.respondsToSelector_(method)) {
                Interceptor.attach(cls[method].implementation, {
                    onEnter: function (args) {
                        console.log("[Bypass] NSURLSessionDelegate SSL challenge");
                        const challenge = new ObjC.Object(args[2]);
                        const sender = challenge.sender();
                        const serverTrust = challenge.protectionSpace().serverTrust();
                        const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                        sender.useCredential_forAuthenticationChallenge_(credential, challenge);
                    }
                });
            }
        }
    } catch (err) {
        console.log("[!] NSURLSessionDelegate hook failed: " + err);
    }

    // Hook NSURLConnectionDelegate
    try {
        const NSURLConnection = ObjC.classes.NSURLConnection;
        Interceptor.attach(NSURLConnection["- connection:willSendRequestForAuthenticationChallenge:"].implementation, {
            onEnter: function (args) {
                console.log("[Bypass] NSURLConnection SSL challenge");
                const challenge = new ObjC.Object(args[3]);
                const sender = challenge.sender();
                const trust = challenge.protectionSpace().serverTrust();
                const credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                sender.useCredential_forAuthenticationChallenge_(credential, challenge);
            }
        });
    } catch (err) {
        console.log("[!] NSURLConnectionDelegate hook failed: " + err);
    }

    // Hook TrustKit if used
    try {
        const TSKPinningValidator = ObjC.classes.TSKPinningValidator;
        Interceptor.attach(TSKPinningValidator["- evaluateTrust:forHostname:"].implementation, {
            onEnter: function (args) {
                console.log("[Bypass] TrustKit evaluateTrust()");
            },
            onLeave: function (retval) {
                retval.replace(0); // TSKTrustEvaluationSuccess
                console.log("[Bypass] TrustKit evaluation bypassed");
            }
        });
    } catch (err) {
        console.log("[!] TrustKit hook failed: " + err);
    }

    // BoringSSL hook
    try {
        const tlsPeerTrust = Module.findExportByName("libcoretls_cfhelpers.dylib", "tls_helper_create_peer_trust");
        if (tlsPeerTrust) {
            Interceptor.attach(tlsPeerTrust, {
                onEnter: function () {
                    console.log("[Bypass] tls_helper_create_peer_trust() bypassed");
                },
                onLeave: function (retval) {
                    retval.replace(0);
                }
            });
        }
    } catch (err) {
        console.log("[!] BoringSSL bypass failed: " + err);
    }

    // CFNetwork SSLSetSessionOption
    try {
        const sslSetSessionOption = Module.findExportByName("Security", "SSLSetSessionOption");
        if (sslSetSessionOption) {
            Interceptor.attach(sslSetSessionOption, {
                onEnter: function (args) {
                    const option = args[1].toInt32();
                    // kSSLSessionOptionBreakOnServerAuth = 0
                    if (option === 0) {
                        console.log("[Bypass] SSLSetSessionOption() - BreakOnServerAuth disabled");
                        args[2] = ptr("0x0");
                    }
                }
            });
        }
    } catch (err) {
        console.log("[!] SSLSetSessionOption hook failed: " + err);
    }

    console.log("[*] All SSL pinning bypass hooks installed.");
} else {
    console.log("[-] Objective-C runtime is not available!");
}
