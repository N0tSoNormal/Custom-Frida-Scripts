// Combined Anti-Frida + Java SSL + Native SSL + Proxy bypass

'use strict';

function safeLog() {
    try {
        console.log.apply(console, arguments);
    } catch (e) {}
}

function findAndAttach(nameList, onAttach) {
    nameList.forEach(function (name) {
        try {
            var addr = Module.findExportByName(null, name);
            if (!addr) {
                // try common libs
                ['libssl.so','libcrypto.so','libconscrypt.so','libjavacrypto.so','libc.so'].forEach(function(lib){
                    if (!addr) {
                        addr = Module.findExportByName(lib, name);
                    }
                });
            }
            if (addr) {
                safeLog('[+] Found native symbol:', name, '->', addr);
                try { onAttach(addr, name); } catch (e) { safeLog('[!] attach cb failed for', name, e); }
            } else {
                //safeLog('[-] Not found:', name);
            }
        } catch (e) {
            safeLog('[!] findAndAttach error for', name, e);
        }
    });
}


Java.perform(function () {
    safeLog('[*] Java hooks init');

    // --- Anti-Frida: intercept class loads that contain "frida" ---
    try {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
            try {
                if (name && name.toLowerCase().indexOf('frida') !== -1) {
                    safeLog('[Java] Detected class load:', name);
                    // try to hook methods lazily (may throw if class not yet fully linked)
                    try {
                        var klass = Java.use(name);
                        var methods = klass.class.getDeclaredMethods();
                        methods.forEach(function (m) {
                            var mName = m.getName();
                            try {
                                klass[mName].overloads.forEach(function (ov) {
                                    ov.implementation = function () {
                                        safeLog('[Java Bypass] ' + name + '.' + mName + '() -> return false/null');
                                        // prefer returning false for boolean methods
                                        try {
                                            if (ov.returnType && ov.returnType.class && ov.returnType.class.getName().toLowerCase().indexOf('boolean') !== -1) {
                                                return false;
                                            }
                                        } catch (e) {}
                                        return null;
                                    };
                                });
                            } catch (e) {}
                        });
                    } catch (e) { safeLog('[Java] hook class failed:', name, e); }
                }
            } catch (e) {}
            return this.loadClass(name);
        };
        safeLog('[+] Hooked ClassLoader.loadClass');
    } catch (e) {
        safeLog('[!] Could not hook ClassLoader.loadClass:', e);
    }

    
    try {
        Java.enumerateLoadedClasses({
            onMatch: function (c) {
                if (c.toLowerCase().indexOf('frida') !== -1) {
                    safeLog('[Java enum] Found:', c);
                }
            },
            onComplete: function () { safeLog('[Java enum] complete'); }
        });
    } catch (e) { /* ignore */ }

    
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function (k) {
            try {
                if (k && k.toLowerCase().indexOf('proxy') !== -1) {
                    safeLog('[Proxy Bypass] System.getProperty(' + k + ') -> null');
                    return null;
                }
            } catch (e) {}
            return this.getProperty(k);
        };
        safeLog('[+] Hooked System.getProperty for proxy');
    } catch (e) {
        safeLog('[!] System.getProperty hook failed', e);
    }

    try {
        var Proxy = Java.use('android.net.Proxy');
        if (Proxy.getDefaultHost) {
            Proxy.getDefaultHost.implementation = function () { safeLog('[Proxy Bypass] Proxy.getDefaultHost -> null'); return null; };
        }
        if (Proxy.getDefaultPort) {
            Proxy.getDefaultPort.implementation = function () { safeLog('[Proxy Bypass] Proxy.getDefaultPort -> 0'); return 0; };
        }
        safeLog('[+] Hooked android.net.Proxy defaults (if present)');
    } catch (e) {
        
    }

    -
    try {
        var ProxyInfo = Java.use('android.net.ProxyInfo');
        if (ProxyInfo.getHost) {
            ProxyInfo.getHost.implementation = function () { safeLog('[ProxyInfo] getHost -> null'); return null; };
        }
        if (ProxyInfo.getPort) {
            ProxyInfo.getPort.implementation = function () { safeLog('[ProxyInfo] getPort -> 0'); return 0; };
        }
    } catch (e) {}

    
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManagerImpl = Java.registerClass({
            name: 'dev.bypass.AllTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { /* accept */ },
                checkServerTrusted: function (chain, authType) { /* accept */ },
                getAcceptedIssuers: function () { return []; }
            }
        });

        try {
            var tm = [TrustManagerImpl.$new()];
            var ctx = SSLContext.getInstance('TLS');
            ctx.init(null, tm, null);
            SSLContext.setDefault(ctx);
            safeLog('[+] SSLContext default replaced with permissive TrustManager');
        } catch (e) {
            safeLog('[!] Setting SSLContext default failed', e);
        }
    } catch (e) {
        safeLog('[!] Java TrustManager fallback not available:', e);
    }

    // HostnameVerifier
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (nv) {
            safeLog('[+] setDefaultHostnameVerifier blocked');
            return;
        };
        safeLog('[+] Hooked HttpsURLConnection.setDefaultHostnameVerifier');
    } catch (e) { safeLog('[!] HttpsURLConnection hook failed', e); }

    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        if (HostnameVerifier.verify) {
            HostnameVerifier.verify.implementation = function (hostname, session) {
                safeLog('[+ HostnameVerifier] verify -> true for', hostname);
                return true;
            };
            safeLog('[+] Hooked HostnameVerifier.verify');
        }
    } catch (e) {}

    
    var okClasses = [
        'okhttp3.CertificatePinner', 'okhttp3.OkHttpClient', // common okhttp3
        'okhttp.CertificatePinner', 'com.squareup.okhttp.CertificatePinner' // older/shaded
    ];
    okClasses.forEach(function (cname) {
        try {
            var C = Java.use(cname);
            try {
                if (C.check) {
                    C.check.overload('java.lang.String', 'java.util.List').implementation = function (h, certs) {
                        safeLog('[OkHttp bypass] ' + cname + '.check for ' + h);
                        return;
                    };
                }
            } catch (e) {}
            safeLog('[+] OkHttp class present and hooked:', cname);
        } catch (e) {
            // not present - ignore
        }
    });

    safeLog('[*] Java hooks done');
}); // Java.perform


(function nativeHooks() {
    safeLog('[*] Native hooks init');

    
    var antiNames = ['open', 'openat', 'readlink', 'ptrace', 'access', 'stat', 'stat64', 'fopen'];
    antiNames.forEach(function (n) {
        try {
            // attempt to find in libc or other libs
            var addr = Module.findExportByName('libc.so', n) || Module.findExportByName(null, n);
            if (!addr) {
                // try common android libs
                addr = Module.findExportByName('libc.so', n) || Module.findExportByName('libc.so.6', n);
            }
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            var p = args[0];
                            var s = Memory.readUtf8String(p);
                            if (s && s.toLowerCase().indexOf('frida') !== -1) {
                                safeLog('[Native Bypass] ' + n + '("' + s + '") -> faked not-found');
                                this._fake = true;
                            }
                            // also catch checks for /proc/*/maps or /proc/self/maps
                            if (s && s.indexOf('/proc/') !== -1 && s.indexOf('maps') !== -1) {
                                safeLog('[Native Bypass] ' + n + '("' + s + '") -> faked not-found');
                                this._fake = true;
                            }
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        try {
                            if (this._fake) {
                                // return -1 for many syscalls to indicate failure
                                retval.replace(ptr(-1));
                            }
                        } catch (e) {}
                    }
                });
                safeLog('[+] Hooked native anti-frida target:', n, '->', addr);
            }
        } catch (e) { /* ignore */ }
    });

    
    var sslNames = [
        'SSL_get_verify_result',
        'SSL_set_verify',
        'SSL_CTX_set_verify',
        'SSL_CTX_set_custom_verify',
        'X509_verify_cert',
        'X509_verify',
        'SSL_write', // not for verify but useful to observe
        'SSL_read'
    ];

    findAndAttach(sslNames, function (addr, name) {
        try {
            if (name === 'SSL_get_verify_result' || name === 'X509_verify_cert' || name === 'X509_verify') {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        // nothing
                    },
                    onLeave: function (retval) {
                        try {
                            safeLog('[Native SSL] forcing verification success on', name);
                            // X509_verify returns 1 for success (int), SSL_get_verify_result returns 0 for X509_V_OK
                            if (name.indexOf('SSL_get_verify_result') !== -1) {
                                retval.replace(ptr(0)); // X509_V_OK
                            } else {
                                retval.replace(ptr(1)); // success
                            }
                        } catch (e) {}
                    }
                });
                safeLog('[+] Attached override for', name);
            } else if (name === 'SSL_set_verify' || name === 'SSL_CTX_set_verify') {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            // set verify mode to 0 (no verify)
                            safeLog('[Native SSL] intercepting', name, '-> forcing mode 0 (no verify)');
                            // arg0 is typically ctx/ssl, arg1 is mode
                            if (args.length > 1) {
                                args[1] = ptr(0);
                            }
                        } catch (e) {}
                    }
                });
                safeLog('[+] Attached for', name);
            } else if (name === 'SSL_CTX_set_custom_verify') {
                // try to override the callback arg (third arg)
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            safeLog('[Native SSL] intercepting SSL_CTX_set_custom_verify, patching callback');
                            // arg2 is callback pointer; we replace with harmless callback (if signature matches)
                            var cb = new NativeCallback(function (ssl, x509_store_ctx) {
                                return 1; // success
                            }, 'int', ['pointer', 'pointer']);
                            args[2] = cb;
                        } catch (e) { safeLog('[!] customizing SSL_CTX_set_custom_verify failed', e); }
                    }
                });
                safeLog('[+] Attached for SSL_CTX_set_custom_verify');
            } else {
                // For other read/write observers
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        safeLog('[Native] ' + name + ' called');
                    }
                });
            }
        } catch (e) {
            safeLog('[!] failed to attach to', name, e);
        }
    });

    
    try {
        // common conscrypt symbol(s) to try
        var conscryptSymbols = ['conscrypt::OpenSSLX509Certificate_verify', 'Conscrypt_verify'];
        conscryptSymbols.forEach(function (s) {
            try {
                var a = Module.findExportByName(null, s) || Module.findExportByName('libconscrypt.so', s);
                if (a) {
                    Interceptor.attach(a, {
                        onEnter: function (args) { safeLog('[Conscrypt] ' + s + ' called, forcing success'); },
                        onLeave: function (ret) { try { ret.replace(ptr(1)); } catch (e) {} }
                    });
                    safeLog('[+] hooked conscrypt symbol:', s);
                }
            } catch (e) {}
        });
    } catch (e) {}

    safeLog('[*] Native hooks done (best-effort).');
})(); // nativeHooks


// 3) Extra: hide Frida server from ps / netstat (optional small helpers)

(function hideFridaFromProcs() {
    try {
        // Intercept getdents/getdents64 on libc to filter /proc if needed - advanced and may crash on some devices.
        // We'll be conservative and only hook if we can find getdents64 safely.
        var getdents64 = Module.findExportByName('libc.so', 'getdents64');
        if (getdents64) {
            Interceptor.attach(getdents64, {
                onLeave: function (retval) {
                    try {
                        // TODO: complex filtering - risky. We'll not modify by default.
                    } catch (e) {}
                }
            });
            safeLog('[+] getdents64 present (no modifications to avoid crashes)');
        }
    } catch (e) {}
})();

safeLog('[*] ultimate_bypass.js loaded');
