# AppleID Authentication

## Intro

I began this little side project back in December 2019 and it all started because Cydia Impactor wasn't working on Windows any more. My hobby has always been digging into mobile stuff and in particular the iOS platform and I usually work on the macOS platform when dealing with iOS. Since there wasn't anyone who was working on a Cydia Impactor replacement or trying to fix it, I thought I might dig into it and see where it takes me.

These were just meant to be my notes, but if it has been useful, please ping me and let me know. p.s. It's a long read.

From a high level, this is how Cydia Impactor or XCode works when signing/resigning a package.

1. Login with AppleID.
2. Download signing certificate. If one does not exist, create it.
3. Sign binaries.
4. Zip them up into a .ipa or .app file.

## Technical Details

macOS Mojave 10.14.6
Darwin Kernel Version 18.7.0: Sun Dec  1 18:59:03 PST 2019; root:xnu-4903.278.19~1/RELEASE_X86_64 x86_64

/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd
SHA256 1734d20022891ba26c570ba8120d216985e8803489edb3cac0ccd48b7bf3e175

/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/AuthKit
SHA256 b48d02895585d9152506620ace5ce2538a46e2cca42fae286c84a99448c064ce

/System/Library/PrivateFrameworks/AppleIDAuthSupport.framework/Versions/A/AppleIDAuthSupport
e01c5c5b2761edbc2e72ac0db968e992399f79ffef217a20140222fe3b956b74

## XCode & AppleID

I'm already quite familiar with how .ipa files/binaries are resigned via XCode [https://github.com/vtky/resign], but what I was not familiar with was how XCode performs authentication to retrieve the signing certificates.

When starting XCode and navigating to the accounts sign-in, there would be a process that is started, `/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd`. As it is part of the AuthKit framework, the assumption was that `akd` supports the authentication process. These are the shared libraries that supports `akd`.

```bash
> jtool -L /System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd
    /System/Library/PrivateFrameworks/MobileKeyBag.framework/Versions/A/MobileKeyBag
    /System/Library/PrivateFrameworks/AppleIDAuthSupport.framework/Versions/A/AppleIDAuthSupport
    /System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/AuthKit
    /System/Library/PrivateFrameworks/CommonUtilities.framework/Versions/A/CommonUtilities
    /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices
    /System/Library/PrivateFrameworks/KeychainCircle.framework/Versions/A/KeychainCircle
    /System/Library/PrivateFrameworks/ProtocolBuffer.framework/Versions/A/ProtocolBuffer
    /System/Library/Frameworks/Security.framework/Versions/A/Security
    /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation
    /usr/lib/libobjc.A.dylib
    /usr/lib/libSystem.B.dylib
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
```

Obviously `akd` would connect back to Apple in some way, time to setup a network proxy through Burp and check out the network communications. Unfortunately, certificate pinning got in the way. Fortunately however, @nabla-c0d3 [https://github.com/nabla-c0d3/ssl-kill-switch2] has done most of the work, just need to convert it into a Frida script as I use Frida for almost everything.

```js
/*
    Stuff from nabla-c0d3's SSL Kill Switch 2 (https://github.com/nabla-c0d3/ssl-kill-switch2) converted to run with Frida.
*/
var ssl_ctx_set_custom_verify = new NativeFunction(
    Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify"), 'void', ['pointer', 'int', 'pointer']
);

var ssl_get_psk_identity = new NativeFunction(
    Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity"), 'pointer', ['pointer']
);

function return_zero(ssl, out_alert) {
    return 0;
}

var ssl_verify_result_t = new NativeCallback(function(ssl, out_alert) {
    return_zero(ssl, out_alert);
}, 'int', ['pointer', 'pointer']);

Interceptor.replace(ssl_ctx_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
    ssl_ctx_set_custom_verify(ssl, mode, ssl_verify_result_t);
}, 'void', ['pointer', 'int', 'pointer']));

Interceptor.replace(ssl_get_psk_identity, new NativeCallback(function(ssl) {
    return "bleh";
}, 'pointer', ['pointer']));
```

> macOS doesn't like anyone messing around with system binaries. To get Frida to hook into XCode / akd, System Integrity Protection (SIP) needs to be disabled.
>
> To disable: `csrutil disable` then restart.

From a Burp capture, a total of 4 sets of requests and responses are sent to and received from Apple during the authentication process. One of which didn't appear to be too important to the authentication process, the `POST` to `/grandslam/GsService2/postdata`

```http
POST /grandslam/GsService2/postdata HTTP/1.1
Host: gsas.apple.com
```

The other 3 requests and responses did not make much sense though. To figure out what was going on, a search of strings within `akd` and the linked binaries was performed based on the strings found in the first request.

**Request & Response 1**

```HTTP
POST /grandslam/GsService2 HTTP/1.1
Host: gsa.apple.com

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Header</key>
    <dict>
        <key>Version</key>
        <string>1.0.1</string>
    </dict>
    <key>Request</key>
    <dict>
        <key>A2k</key>
        <data>
            [ BASE64 Encoded Data Blob ]
        </data>
        <key>cpd</key>
        <dict>
            [ TRUNCATED ]
        </dict>
        <key>o</key>
        <string>init</string>
        <key>ps</key>
        <array>
            <string>s2k</string>
            <string>s2k_fo</string>
        </array>
        <key>u</key>
        <string>[ Username ]</string>
    </dict>
</dict>
</plist>


HTTP/1.1 200
Server: Apple

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Response</key>
    <dict>
        <key>Status</key>
        <dict>
            <key>hsc</key>
            <integer>200</integer>
            <key>ed</key>
            <string></string>
            <key>ec</key>
            <integer>0</integer>
            <key>em</key>
            <string></string>
        </dict>
        <key>i</key>
        <integer>20231</integer>
        <key>s</key>
        <data>[ BASE64 Encoded Data Blob ]</data>
        <key>sp</key>
        <string>s2k</string>
        <key>c</key>
        <string>[ UUID Like String ]</string>
        <key>B</key>
        <data>[ BASE64 Encoded Data Blob ]</data>
    </dict>
    <key>Header</key>
    <dict>
    </dict>
</dict>
</plist>

```

**Request & Response 2**

```HTTP
POST /grandslam/GsService2 HTTP/1.1
Host: gsa.apple.com

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Header</key>
    <dict>
        <key>Version</key>
        <string>1.0.1</string>
    </dict>
    <key>Request</key>
    <dict>
        <key>M1</key>
        <data>
            [ BASE64 Encoded Data Blob ]
        </data>
        <key>c</key>
        <string>[ UUID Like String - Same as the 1st response ]</string>
        <key>cpd</key>
        <dict>
            [ TRUNCATED ]
        </dict>
        <key>o</key>
        <string>complete</string>
        <key>u</key>
        <string>[ BASE64 Encoded Data Blob ]</string>
    </dict>
</dict>
</plist>


HTTP/1.1 200
Server: Apple

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Response</key>
    <dict>
        <key>Status</key>
        <dict>
            <key>hsc</key>
            <integer>200</integer>
            <key>ed</key>
            <string></string>
            <key>ec</key>
            <integer>0</integer>
            <key>em</key>
            <string></string>
        </dict>
        <key>spd</key>
        <data>[ BASE64 Encoded Data Blob ]</data>
        <key>M2</key>
        <data>[ BASE64 Encoded Data Blob ]</data>
        <key>np</key>
        <data>[ BASE64 Encoded Data Blob ]</data>
    </dict>
    <key>Header</key>
    <dict>
    </dict>
</dict>
</plist>
```

**Request & Response 3**

```HTTP
POST /grandslam/GsService2 HTTP/1.1
Host: gsa.apple.com

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Header</key>
    <dict>
        <key>Version</key>
        <string>1.0.1</string>
    </dict>
    <key>Request</key>
    <dict>
        <key>app</key>
        <array>
            <string>com.apple.gs.xcode.auth</string>
        </array>
        <key>c</key>
        <data>
            [ BASE64 Encoded Data Blob ]
        </data>
        <key>checksum</key>
        <data>
            [ BASE64 Encoded Data Blob ]
        </data>
        <key>cpd</key>
        <dict>
            [ TRUNCATED ]
        </dict>
        <key>o</key>
        <string>apptokens</string>
        <key>t</key>
        <string>[ BASE64 Encoded Data Blob ]</string>
        <key>u</key>
        <string>[ UUID Like String - Different from previous ]</string>
    </dict>
</dict>
</plist>


HTTP/1.1 200
Server: Apple

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Response</key>
    <dict>
        <key>Status</key>
        <dict>
            <key>hsc</key>
            <integer>200</integer>
            <key>ed</key>
            <string></string>
            <key>ec</key>
            <integer>0</integer>
            <key>em</key>
            <string></string>
        </dict>
        <key>et</key>
        <data>[ BASE64 Encoded Data Blob ]</data>
    </dict>
    <key>Header</key>
    <dict>
    </dict>
</dict>
</plist>
```

The string `A2k` and `cpd` was found in the `AppleIDAuthSupport.framework`. Decompilation and analysis led to the following functions are where the magic happens,

- _AppleIDAuthSupportCreate()
- _stateClientNeg1()
- _stateClientNeg2()
- _stateClientNeg3()

It was found that Apple's authentication process used the Secure Remote Password 6a protocol (SRP-6a).

> ### What is SRP-6a?
>
> It is common for an authentication scheme / developers to store passwords in a hashed format, something along the lines of H(salt, password) where H is a hashing algorithm such as SHA-1/SHA-256 or bcrypt/scrypt. The following is a simplified explination, for those interested in the detailed walkthrough and math, visit [http://srp.stanford.edu/]
>
> The SRP-6a protocol [http://srp.stanford.edu/design.html] [https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol] however is a zero-knowledge password proof, this means that a client can to prove to the server that it knows a password, without actually needing to transmit the password, whether in clear, hashed or encrypted format, over the network.
>
> When a user account is first created, the following will be generated,
>
> - A private key, x = H(s, p)
>   - H = One-way hash function
>   - s = Salt
>   - p = User password
> - Password verifier, v = g^x
>   - g = A generator of the multiplicative group modulo N
>   - x = The private key derived above
>
> The server will then only store {I, s, v} where I = Username, s = salt and v = password verifier. If Apple's user database were to be compromised, it would make it significantly harder for an attacker to retrieve any user's password and render rainbow table attacks infeasible.
>
> A user is now able to authenticate to the server in the following manner,
>
> 1. The user/client will need to request the salt from the server. It generates a public/private keypair and the username and public key is sent to the server.
> 2. The server will also generate its own public/private keypair and return to the user/client the salt and the server's public key.
> 3. The user/client will now derive x and then compute a session key, S = (x, client private key, server public key)
> 4. The server will also generate a session key, S = (v, client public key, server private key)
>
> Now, both parties will then be able to send messages encrypted with the session key to each other, and assuming they are able to decrypt and read the messages, it now proves to each other that, the user/client knows the password and that the server that the client is communicating with is not an imposter.

Going through the above functions, there are a couple interesting functions that are part of Apple's CoreCrypto library used as part of Apple's implementation of the SRP protocol,

- ccsha256_di()
- ccpbkdf2_hmac()
- ccsrp_gp_rfc5054_2048()
- ccaes_cbc_decrypt_mode()
- cchmac()
- ccpad_pkcs7_decrypt()
- ccaes_gcm_decrypt_mode()

Back to the requests and responses, from the strings / logging comments in the decompilation and the open sourced CoreCrypto library it was possibile to identify what some of the parameters are.

| Key | Comment |
|--|--|
| A2k | Client public key |
| u | Apple ID Username |
| i | Iteration (For the PBKDF2 function) |
| s | Salt |
| c | Cookie |
| B | Server Public Key |

The above should be enough to begin a replication of the first phase, however, there is a component within the request, `cpd`, that hasn't yet been analyzed. The `cpd` section was the same throughout all 3 requests. With a little help from Google and AuthKit, the following was pieced together. Didn't figure out what all of them meant, but I believe I got the important ones.

```xml
<key>cpd</key>
<dict>
    <key>X-Apple-I-Client-Time</key>
    <string>2020-XX-XXTXX:XX:XXZ</string>
    <key>X-Apple-I-MD</key>                 <-- Anisette Headers (oneTimePassword)
    <string>[ BASE64 Encoded Data Blob ]</string>
    <key>X-Apple-I-MD-LU</key>              <-- Anisette Headers (localUserUUID)
    <string>[ Hex String ]</string>
    <key>X-Apple-I-MD-M</key>               <-- Anisette Headers (machineID)
    <string>[ BASE64 Encoded Data Blob ]</string>
    <key>X-Apple-I-MD-RINFO</key>           <-- Anisette Headers (routingInfo)
    <string>17106176</string>
    <key>X-Apple-I-MLB</key>                <-- Main Logic Board Serial
    <string>XXXXXXXXX</string>
    <key>X-Apple-I-ROM</key>                <-- ROM Address
    <string>XXXXXXXXX</string>
    <key>X-Apple-I-SRL-NO</key>             <-- Serial number of Mac hardware
    <string>XXXXXXXXX</string>
    <key>X-Mme-Device-Id</key>              <-- Hardware UUID
    <string>XXXXXXXXX</string>
    <key>bootstrap</key>
    <true/>
    <key>capp</key>
    <string>Xcode</string>
    <key>ckgen</key>
    <true/>
    <key>dc</key>
    <string>#9d9da0</string>
    <key>icscrec</key>
    <true/>
    <key>loc</key>
    <string>en_US</string>
    <key>pbe</key>
    <false/>
    <key>prkgen</key>
    <true/>
    <key>svct</key>
    <string>iCloud</string>
</dict>
```

A very cool way to find some of the above information is to use MacInfoPkg by the team over at [https://github.com/acidanthera/MacInfoPkg], it also allows you to generate serial numbers and MLBs. `routingInfo` and `localUserUUID` doesn't change across various requests and reboots, but from the decompilation `localUserUUID` is generated based on some details of the current logged in user.

The remaining 2 interesting parts are `oneTimePassword` and `machineID`. These 2 values appear to be randomly generated and led me down a rabbit hole. Unfortunately, after a couple days, I was not fully able to piece together how these values were generated, but I also remembered that the aim is to replicate this process on a Microsoft Windows platform.

Going through other Apple applications on macOS, `X-Apple-I-MD` and `X-Apple-I-MD-M` appeared in other communications as well, iTunes, App Store, etc. Since, `scvt` mentioned `iCloud` my brain led me to install iCloud on Windows and check if the `X-Apple-I-MD` and `X-Apple-I-MD-M` values were in use. A string search revealed several DLLs containing the string `X-Apple-` and `OTP`. Of particular interest was the `AOSKit.dll` file, mainly because there was a corresponding PrivateFramework named AOSKit and there were the strings `applyOTPHeadersForDSID:` and  `retrieveOTPHeadersForDSID:`.

A quick class-dump of `AOSKit.framework` showed only the `retrieveOTPHeadersForDSID:` existed and was part of the `AOSUtilities` class. Couple other interesting methods in there,

```
+ (id)currentComputerName;
+ (id)machineUDID;
+ (id)machineSerialNumber;
```

Problem is now understanding the method and how to call it. Fortunately it only takes in a single parameter.

<img src="https://github.com/vtky/AppleIDAuth/raw/master/images/AOSUtilities_decompilation.png" alt="AOSUtilities Decompilation" width="500"/>

From the decompilation, it initializes a `NSMutableDictionary` which also appears to be the output, and then takes a string input parameter and formats it as a `NSNumber`. After trying several values, only `-1` and `-2` would produce a result.

```
2020-01-12 17:14:56.717084+0800 AOSKit[88523:3902502] {
    "X-Apple-MD" = "[ BASE64 Encoded Data Blob ]";
    "X-Apple-MD-M" = "[ BASE64 Encoded Data Blob ]";
}
2020-01-12 17:14:56.717154+0800 AOSKit[88523:3902502] {
    "X-Apple-MD" = "[ BASE64 Encoded Data Blob ]"; <-- Different value from above
    "X-Apple-MD-M" = "[ BASE64 Encoded Data Blob ]"; <-- Same value as above
}
```

> XCode project: 
> 
> Note, to create .tbd:
> 
> `xcrun tapi stubify -o AOSKit.tbd /System/Library/PrivateFrameworks/AOSKit.framework/AOSKit`

## Building a Windows App

