package pt.unl.fct.di.apdc.firstwebapp.Authentication;

import java.util.Base64;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignatureUtils {

    private static final Logger LOG = Logger.getLogger(SignatureUtils.class.getName());

    public static final String ALGORITHM = "HmacSHA256";

    public static String calculateHMac(String key, String data) {
        try {
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);

            Mac sha256_HMAC = Mac.getInstance(ALGORITHM);
            sha256_HMAC.init(secret_key);

            return base64Enconder(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
        } catch (Exception e) {
            LOG.severe("Error while signing. " + e.toString());
        }

        return null;
    }

    public static String byteArrayToHex(byte[] str) {
        StringBuilder sb = new StringBuilder(str.length * 2);
        for (byte b : str)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String base64Enconder(byte[] str) {
        String encodedString = Base64.getEncoder().encodeToString(str);
        return encodedString;
    }

    public static boolean verifyHMac(String key, String data, String signature) {
        String calculatedSignature = calculateHMac(key, data);
        return calculatedSignature.equals(signature);
    }

}
