package com.faiyaz.ondc.authheaderjava;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// import java.io.PrintWriter;
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
// import java.io.File;
// import java.io.FileNotFoundException;

@Controller
@RestController
public class AuthController {
   
    static String privateKey = "dXwaXaJDJteluzzvNhWS7FAaXoeyTEJkhwUtV5kyDQE="; //
    static String publicKey = "UCIm0tWcd/Iy8Gvnqzxy0KPDa6Fk//yajrk/WEVZBpU=";
    static String kid = "api.greenreceipt.in|28843C15-9764-4245-92CF-7D236B855711|ed25519";

    @PostMapping("/generateheaderjava")
    @ResponseBody
    
    public String auth(@RequestBody String req) {
    setup();

    try {
        StringBuilder sb = new StringBuilder();
        UUID uuid = UUID.randomUUID();
        String generatedString = uuid.toString();

        System.out.println("Your UUID is: " + generatedString);

        
                //String req = "{\"context\":{\"domain\":\"nic2004:52110\",\"country\":\"IND\",\"city\":\"std:080\",\"action\":\"search\",\"core_version\":\"1.1.0\",\"bap_id\":\"buyer-app-preprod.ondc.org\",\"bap_uri\":\"https://buyer-app-preprod.ondc.org/protocol/v1\",\"transaction_id\":\"aced8868-b750-429c-8ae9-d85a6e1f8f95\",\"message_id\":\"ffe8452b-c9ce-4095-a7c6-3df3560ced28\",\"timestamp\":\"2023-03-07T08:27:39.927Z\",\"ttl\":\"PT30S\"},\"message\":{\"intent\":{\"item\":{\"descriptor\":{\"name\":\"pizzaa\"}},\"fulfillment\":{\"type\":\"Delivery\",\"end\":{\"location\":{\"gps\":\"12.96774,77.588913\"}}},\"payment\":{\"@ondc/org/buyer_app_finder_fee_type\":\"percent\",\"@ondc/org/buyer_app_finder_fee_amount\":\"2.0\"}}}}";
                

                long testTimestamp = System.currentTimeMillis() / 1000L;

                sb.append(req);
                sb.append("^");
                System.out.println("Test Timestamp :" + testTimestamp);

                System.out.println("\n==============================Json Request===================================");
                System.out.println(req);

                String blakeValue;
                try {
                    blakeValue = generateBlakeHash(req);

                    System.out.println(
                            "\n==============================Digest Value ===================================");
                    System.out.println(blakeValue);
                    String signingString = "(created): " + testTimestamp + "\n(expires): " + (testTimestamp + 60000)
                            + "\ndigest: BLAKE-512=" + blakeValue + "";

                    System.out
                            .println("\n==============================Data to Sign===================================\n");
                    System.out.println(signingString);

                    String header = "(" + testTimestamp + ") (" + (testTimestamp + 60000) + ") BLAKE-512=" + blakeValue
                            + "";
                    System.out.println("\nHeader:  " + header);

                    String signedReq = generateSignature(signingString, privateKey);

                    System.out.println("\nSignature : " + signedReq);

        String authHeader = "Signature keyId=\"" + kid + "\",algorithm=\"ed25519\", created=\""
            + testTimestamp + "\", expires=\"" + (testTimestamp + 60000)
            + "\", headers=\"(created) (expires) digest\", signature=\"" + signedReq + "\"";

            System.out.println("Authorization Header:   "+ authHeader);

            // To Verify Signature
            System.out.println(
                "\n==============================Verify Signature================================");

        verifySignature(signedReq, signingString, publicKey);
                
        return authHeader;
                
    } catch (Exception e) {
        e.printStackTrace();
    }

    }catch(Exception e){
        System.out.println(e.getMessage());
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
        // System.out.println(bs64);
        return bs64;

    }


    public static boolean verifySignature(String sign, String requestData, String dbPublicKey) {
        boolean isVerified = false;
        try {
            System.out.println("Sign : " + sign + " requestData : " + requestData + " PublicKey : " + dbPublicKey);
            // Ed25519PublicKeyParameters publicKey = new
            // Ed25519PublicKeyParameters(Hex.decode(dbPublicKey), 0);
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

