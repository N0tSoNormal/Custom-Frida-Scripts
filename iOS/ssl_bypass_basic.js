// iOS SSL Pinning Bypass (Basic)
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLSessionTask = ObjC.classes.NSURLSessionTask;

    var hookTrust = function() {
        var SecTrustEvaluate = new NativeFunction(
            Module.findExportByName("Security", "SecTrustEvaluate"),
            'int', ['pointer', 'pointer']
        );
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            console.log("[+] SecTrustEvaluate called");
            return 0;
        }, 'int', ['pointer', 'pointer']));

        var SecTrustEvaluateWithError = new NativeFunction(
            Module.findExportByName("Security", "SecTrustEvaluateWithError"),
            'int', ['pointer', 'pointer']
        );
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
            console.log("[+] SecTrustEvaluateWithError called");
            return 1;
        }, 'int', ['pointer', 'pointer']));
    };
    hookTrust();
}