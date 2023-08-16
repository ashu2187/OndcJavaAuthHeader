package com.faiyaz.ondc.authheaderjava;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;
import java.util.UUID;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Controller
@RestController
public class AuthController {
    

    //     static String privateKey = "dXwaXaJDJteluzzvNhWS7FAaXoeyTEJkhwUtV5kyDQE="; //
//     static String publicKey = "UCIm0tWcd/Iy8Gvnqzxy0KPDa6Fk//yajrk/WEVZBpU=";
//     static String kid = "api.greenreceipt.in|28843C15-9764-4245-92CF-7D236B855711|ed25519";

    @PostMapping("/generateheaderjava")
    @ResponseBody
    public String auth(@RequestBody String req,
                       @RequestHeader("privatekey") String privateKey,
                       @RequestHeader("publickey") String publicKey,
                        @RequestHeader("subscriberId") String subscriberId,
                       @RequestHeader("uniquekey") String uniquekey) {
        setup();

        try {
            StringBuilder sb = new StringBuilder();
            UUID uuid = UUID.randomUUID();
            String generatedString = uuid.toString();

            System.out.println("Your UUID is: " + generatedString);

            long testTimestamp = System.currentTimeMillis() / 1000L;

            sb.append(req);
            sb.append("^");
            System.out.println("Test Timestamp :" + testTimestamp);
            
            String ukid = uniquekey;
            String kid = subscriberId + ukid + "|ed25519";

            //
            System.out.println("privateKey:  "+ privateKey);
            System.out.println("publicKey:  "+ publicKey);
            System.out.println("kid:  "+ kid);
            //

            System.out.println("\n==============================Json Request===================================");
            System.out.println(req);

            String blakeValue = generateBlakeHash(req);

            System.out.println("\n==============================Digest Value ===================================");
            System.out.println(blakeValue);
            String signingString = "(created): " + testTimestamp + "\n(expires): " + (testTimestamp + 60000)
                    + "\ndigest: BLAKE-512=" + blakeValue + "";

            System.out.println("\n==============================Data to Sign===================================\n");
            System.out.println(signingString);

            String header = "(" + testTimestamp + ") (" + (testTimestamp + 60000) + ") BLAKE-512=" + blakeValue + "";
            System.out.println("\nHeader:  " + header);

            String signedReq = generateSignature(signingString, privateKey);

            System.out.println("\nSignature : " + signedReq);

            String authHeader = "Signature keyId=\"" + kid + "\",algorithm=\"ed25519\", created=\""
                    + testTimestamp + "\", expires=\"" + (testTimestamp + 60000)
                    + "\", headers=\"(created) (expires) digest\", signature=\"" + signedReq + "\"";

            System.out.println("Authorization Header:   "+ authHeader);

            verifySignature(signedReq, signingString, publicKey);

            return authHeader;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String generateSignature(String req, String pk) {
        String signature = null;
        try {
            Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(
                    Base64.getDecoder().decode(pk.getBytes()), 0);
            Signer sig = new Ed25519Signer();
            sig.init(true, privateKey);
            sig.update(req.getBytes(), 0, req.length());
            byte[] s1 = sig.generateSignature();
            signature = Base64.getEncoder().encodeToString(s1);
        } catch (DataLengthException | CryptoException e) {
            e.printStackTrace();
        }
        return signature;
    }

    public static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println(Security.addProvider(new BouncyCastleProvider()));
        }
    }

    public static String generateBlakeHash(String req) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("BLAKE2B-512", BouncyCastleProvider.PROVIDER_NAME);
        digest.reset();
        digest.update(req.getBytes(StandardCharsets.UTF_8));
        byte[] hash = digest.digest();
        String bs64 = Base64.getEncoder().encodeToString(hash);
        return bs64;
    }

    public static boolean verifySignature(String sign, String requestData, String dbPublicKey) {
        boolean isVerified = false;
        try {
            Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
                    Base64.getDecoder().decode(dbPublicKey), 0);
            Signer sv = new Ed25519Signer();
            sv.init(false, publicKey);
            sv.update(requestData.getBytes(), 0, requestData.length());

            byte[] decodedSign = Base64.getDecoder().decode(sign);
            isVerified = sv.verifySignature(decodedSign);
            System.out.println("Is Sign Verified : " + isVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isVerified;
    }

}


// package com.faiyaz.ondc.authheaderjava;

// import org.springframework.http.HttpHeaders;
// import org.springframework.stereotype.Controller;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.ResponseBody;
// import org.springframework.web.bind.annotation.RestController;

// import java.nio.charset.StandardCharsets;
// import java.security.MessageDigest;
// import java.security.Security;
// import java.util.Base64;
// import java.util.UUID;

// import org.bouncycastle.crypto.CryptoException;
// import org.bouncycastle.crypto.DataLengthException;
// import org.bouncycastle.crypto.Signer;
// import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
// import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
// import org.bouncycastle.crypto.signers.Ed25519Signer;
// import org.bouncycastle.jce.provider.BouncyCastleProvider;

// @Controller
// @RestController
// public class AuthController {

//     @PostMapping("/generateheaderjava")
//     @ResponseBody
//     public String auth(@RequestBody String req, HttpHeaders headers) {
//         setup();

//         try {
//             String privateKey = headers.getFirst("privatekey");
//             String publicKey = headers.getFirst("publickey");
//             String kid = headers.getFirst("kid");

//             StringBuilder sb = new StringBuilder();
//             UUID uuid = UUID.randomUUID();
//             String generatedString = uuid.toString();

//             System.out.println("Your UUID is: " + generatedString);

//             long testTimestamp = System.currentTimeMillis() / 1000L;

//             sb.append(req);
//             sb.append("^");
//             System.out.println("Test Timestamp :" + testTimestamp);

//             System.out.println("\n==============================Json Request===================================");
//             System.out.println(req);

//             String blakeValue = generateBlakeHash(req);

//             System.out.println("\n==============================Digest Value ===================================");
//             System.out.println(blakeValue);
//             String signingString = "(created): " + testTimestamp + "\n(expires): " + (testTimestamp + 60000)
//                     + "\ndigest: BLAKE-512=" + blakeValue + "";

//             System.out.println("\n==============================Data to Sign===================================\n");
//             System.out.println(signingString);

//             String header = "(" + testTimestamp + ") (" + (testTimestamp + 60000) + ") BLAKE-512=" + blakeValue + "";
//             System.out.println("\nHeader:  " + header);

//             String signedReq = generateSignature(signingString, privateKey);

//             System.out.println("\nSignature : " + signedReq);

//             String authHeader = "Signature keyId=\"" + kid + "\",algorithm=\"ed25519\", created=\""
//                     + testTimestamp + "\", expires=\"" + (testTimestamp + 60000)
//                     + "\", headers=\"(created) (expires) digest\", signature=\"" + signedReq + "\"";

//             System.out.println("Authorization Header:   "+ authHeader);

//             verifySignature(signedReq, signingString, publicKey);

//             return authHeader;

//         } catch (Exception e) {
//             e.printStackTrace();
//         }

//         return null;
//     }

//     public static String generateSignature(String req, String pk) {
//         String signature = null;
//         try {
//             Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(
//                     Base64.getDecoder().decode(pk.getBytes()), 0);
//             Signer sig = new Ed25519Signer();
//             sig.init(true, privateKey);
//             sig.update(req.getBytes(), 0, req.length());
//             byte[] s1 = sig.generateSignature();
//             signature = Base64.getEncoder().encodeToString(s1);
//         } catch (DataLengthException | CryptoException e) {
//             e.printStackTrace();
//         }
//         return signature;
//     }

//     public static void setup() {
//         if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
//             Security.addProvider(new BouncyCastleProvider());
//             System.out.println(Security.addProvider(new BouncyCastleProvider()));
//         }
//     }

//     public static String generateBlakeHash(String req) throws Exception {
//         MessageDigest digest = MessageDigest.getInstance("BLAKE2B-512", BouncyCastleProvider.PROVIDER_NAME);
//         digest.reset();
//         digest.update(req.getBytes(StandardCharsets.UTF_8));
//         byte[] hash = digest.digest();
//         String bs64 = Base64.getEncoder().encodeToString(hash);
//         return bs64;
//     }

//     public static boolean verifySignature(String sign, String requestData, String dbPublicKey) {
//         boolean isVerified = false;
//         try {
//             Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(
//                     Base64.getDecoder().decode(dbPublicKey), 0);
//             Signer sv = new Ed25519Signer();
//             sv.init(false, publicKey);
//             sv.update(requestData.getBytes(), 0, requestData.length());

//             byte[] decodedSign = Base64.getDecoder().decode(sign);
//             isVerified = sv.verifySignature(decodedSign);
//             System.out.println("Is Sign Verified : " + isVerified);
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//         return isVerified;
//     }
// }
