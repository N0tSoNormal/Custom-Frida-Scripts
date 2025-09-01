'use strict';

if (ObjC.available) {
  console.log("[*] N0tSoNormal Custom Script: Installing iOS SSL pinning bypass hooks...");

  // Hook NSURLSession delegate method: URLSession:didReceiveChallenge:completionHandler:
  try {
    const NSURLSessionDelegate = ObjC.classes.NSURLSession;
    const methods = NSURLSessionDelegate.$ownMethods;

    for (const method of methods) {
      if (method.includes("URLSession:didReceiveChallenge:completionHandler:")) {
        Interceptor.attach(NSURLSessionDelegate[method].implementation, {
          onEnter: function (args) {
            console.log("[Bypass][NSURLSession] didReceiveChallenge intercepted");

            // Args:
            // args[2] = challenge
            // args[3] = completionHandler

            // Bypass logic:
            const challenge = new ObjC.Object(args[2]);
            const protectionSpace = challenge.protectionSpace();
            const authMethod = protectionSpace.authenticationMethod().toString();

            if (authMethod === "NSURLAuthenticationMethodServerTrust") {
              const serverTrust = protectionSpace.serverTrust();
              const completionHandler = new ObjC.Block(args[3]);

              const NSURLSessionAuthChallengeDisposition = {
                UseCredential: 0,
                PerformDefaultHandling: 1,
                CancelAuthenticationChallenge: 2,
                RejectProtectionSpace: 3
              };

              const credential = ObjC.classesNSURLCredential.credentialForTrust_(serverTrust);
              console.log("  [✓] SSL pinning bypass: trusting server");

              completionHandler.implementation(NSURLSessionAuthChallengeDisposition.UseCredential, credential);
            }
          }
        });
      }
    }
  } catch (e) {
    console.log("[!] Failed to hook NSURLSession delegate: " + e);
  }

  // Hook NSURLConnection: willSendRequestForAuthenticationChallenge:
  try {
    const Delegate = ObjC.classes.NSURLConnection;

    Interceptor.attach(Delegate["- connection:willSendRequestForAuthenticationChallenge:"].implementation, {
      onEnter: function (args) {
        console.log("[Bypass][NSURLConnection] Authentication challenge intercepted");

        const challenge = new ObjC.Object(args[3]);
        const protectionSpace = challenge.protectionSpace();
        const authMethod = protectionSpace.authenticationMethod().toString();

        if (authMethod === "NSURLAuthenticationMethodServerTrust") {
          const serverTrust = protectionSpace.serverTrust();
          const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
          challenge.sender().useCredential_forAuthenticationChallenge_(credential, challenge);
          console.log("  [✓] SSL pinning bypass: accepted in NSURLConnection");
        }
      }
    });
  } catch (e) {
    console.log("[!] Failed to hook NSURLConnection: " + e);
  }

  // Hook TrustKit’s TSKPinningValidator
  try {
    const TSKValidator = ObjC.classes.TSKPinningValidator;
    TSKValidator["- evaluateTrust:forHostname:"].implementation = function (trust, hostname) {
      console.log("[Bypass][TrustKit] evaluateTrust bypassed for host: " + hostname.toString());
      return true;
    };
  } catch (e) {
    console.log("[!] TrustKit not found or hook failed: " + e);
  }

  // Optional: Bypass SecTrustEvaluate (system-level pinning, older apps)
  try {
    const secTrustEval = Module.findExportByName(null, "SecTrustEvaluate");
    if (secTrustEval) {
      Interceptor.attach(secTrustEval, {
        onLeave: function (retval) {
          console.log("[Bypass][SecTrustEvaluate] forced to return success");
          retval.replace(1); // True
        }
      });
    }

    const secTrustEvalWithError = Module.findExportByName(null, "SecTrustEvaluateWithError");
    if (secTrustEvalWithError) {
      Interceptor.attach(secTrustEvalWithError, {
        onLeave: function (retval) {
          console.log("[Bypass][SecTrustEvaluateWithError] forced to return success");
          retval.replace(1);
        }
      });
    }
  } catch (e) {
    console.log("[!] Failed to hook SecTrustEvaluate: " + e);
  }

  console.log("[*] iOS SSL pinning bypass installed.");
}
