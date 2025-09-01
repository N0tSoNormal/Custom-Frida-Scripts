'use strict';

if (ObjC.available) {
    console.log("[*] N0tSoNormal Custom Logic Discovery Script: Injected into Objective-C runtime");

    try {
        const methods = ObjC.classes.NSURLSession.$ownMethods;
        for (const method of methods) {
            if (method.includes("URLSession:didReceiveChallenge:completionHandler:")) {
                console.log("[*] Hooking NSURLSession delegate: " + method);
                Interceptor.attach(ObjC.classes.NSURLSession[method].implementation, {
                    onEnter(args) {
                        const challenge = new ObjC.Object(args[2]);
                        const host = challenge.protectionSpace().host();
                        const method = challenge.protectionSpace().authenticationMethod();
                        console.log("[Intercept][NSURLSession] Host: " + host + ", Method: " + method);
                        console.log("[!] Stack trace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                });
            }
        }
    } catch (e) {
        console.log("[!] NSURLSession hook error: " + e);
    }


    try {
        const connCls = ObjC.classes.NSURLConnection;
        const selector = "- connection:willSendRequestForAuthenticationChallenge:";
        if (connCls && connCls[selector]) {
            Interceptor.attach(connCls[selector].implementation, {
                onEnter(args) {
                    console.log("[Intercept][NSURLConnection] Challenge received");
                    console.log("[!] Stack trace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
        }
    } catch (e) {
        console.log("[!] NSURLConnection hook error: " + e);
    }


    const keywords = ["trust", "ssl", "pin", "cert"];
    const suspicious = [];

    ObjC.enumerateLoadedClasses({
        onMatch(name, owner) {
            if (keywords.some(k => name.toLowerCase().includes(k))) {
                suspicious.push(name);
            }
        },
        onComplete() {
            console.log("[*] Suspicious SSL classes:");
            suspicious.forEach(cls => console.log("  ↳ " + cls));
        }
    });


    function hookSecTrustEvaluate() {
        const name = "SecTrustEvaluate";
        const addr = Module.findExportByName(null, name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) {
                    console.log("[Native] SecTrustEvaluate called");
                    this.start = Date.now();
                },
                onLeave(retval) {
                    console.log("  ↳ Returned: " + retval + " (forced bypass: 1)");
                    retval.replace(1); // force trust
                }
            });
        }
    }

    function hookSecTrustEvalWithError() {
        const name = "SecTrustEvaluateWithError";
        const addr = Module.findExportByName(null, name);
        if (addr) {
            Interceptor.attach(addr, {
                onLeave(retval) {
                    console.log("[Native] SecTrustEvaluateWithError called. Forcing pass.");
                    retval.replace(1);
                }
            });
        }
    }

    hookSecTrustEvaluate();
    hookSecTrustEvalWithError();


    const ssl_write = Module.findExportByName("libssl.dylib", "SSL_write");
    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter(args) {
                const len = args[2].toInt32();
                console.log(`[libssl] SSL_write len=${len}`);
            }
        });
    }

    const ssl_read = Module.findExportByName("libssl.dylib", "SSL_read");
    if (ssl_read) {
        Interceptor.attach(ssl_read, {
            onEnter(args) {
                const len = args[2].toInt32();
                console.log(`[libssl] SSL_read len=${len}`);
            }
        });
    }

} else {
    console.log("[-] Objective-C runtime not available.");
}
