if (ObjC.available) {
    console.log("[*] N0tSoNormal Custom iOS SSL Pinning Bypass Loaded");

    var NSURLSession = ObjC.classes.NSURLSession;
    var delegateMethod = "- URLSession:didReceiveChallenge:completionHandler:";
    var NSURLSessionDelegate = NSURLSession.delegate();

    if (NSURLSessionDelegate && NSURLSessionDelegate.respondsToSelector_(delegateMethod)) {
        Interceptor.attach(NSURLSessionDelegate[delegateMethod].implementation, {
            onEnter: function (args) {
                var block = new ObjC.Block(args[3]);
                var completionHandler = block.implementation;
                block.implementation = function (challenge, disposition, credential) {
                    console.log("[+] Bypassed NSURLSession SSL pinning");
                    completionHandler(challenge, 1, null);
                };
            }
        });
    }

    var setDelegate = ObjC.classes.NSURLConnection["- setDelegate:"];
    if (setDelegate) {
        Interceptor.attach(setDelegate.implementation, {
            onEnter: function (args) {
                console.log("[+] Bypassed NSURLConnection SSL pinning");
            }
        });
    }
}