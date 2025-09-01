Java.perform(function () {
    console.log("[*] N0tSoNormal Custom Android SSL Pinning Bypass Loaded");

    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            console.log("[+] Bypassed OkHttp3 CertificatePinner.check()");
            return;
        };
    } catch (err) {}

    try {
        var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
        OkHttpClient.setCertificatePinner.implementation = function (pinner) {
            console.log("[+] Bypassed OkHttp setCertificatePinner()");
            return this.setCertificatePinner(null);
        };
    } catch (err) {}

    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManager = Java.registerClass({
        name: 'org.anti.ssl.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContextInit = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    );
    SSLContextInit.implementation = function (k, t, s) {
        console.log("[+] Overriding SSLContext.init() with custom TrustManager");
        return SSLContextInit.call(this, k, TrustManagers, s);
    };

    console.log("[*] SSL pinning bypass applied");
});