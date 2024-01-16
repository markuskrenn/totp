package at.mk.totp.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;


public class TotpData
{
    public enum Algorithm {
        SHA1   ("HmacSHA1",   "SHA1"),
        SHA256 ("HmacSHA256", "SHA256"),
        SHA512 ("HmacSHA512", "SHA512");

        private final String hmac_algorithm;
        private final String qrcode_name;

        Algorithm (String hmac_algorithm, String qrcode_name) {
            this.hmac_algorithm = hmac_algorithm;
            this.qrcode_name   = qrcode_name;
        }

        public String getHmacAlgorithm () {
            return hmac_algorithm;
        }

        public String getQrcodeName () {
            return qrcode_name;
        }
    }

    private String     label;                        // account name (e.g. username, email, ...)
    private String     secret;                       // the secret used for OTP generation
    private String     issuer;                       // application name
    private Algorithm  algorithm  = Algorithm.SHA1;  // hash algorithm used for OTP generation
    private int        digits     =  6;              // number of digits of final OTP
    private int        period     = 30;              // number of seconds for valid OTP


    public TotpData label (String label) {
        this.label = label;
        return this;
    }

    public TotpData secret (String secret) {
        this.secret = secret;
        return this;
    }

    public TotpData random_secret () {
        var numCharacters = 32;
        var bytes         = new byte[(numCharacters*5)/8];  // 5 bits per char in base32
        new SecureRandom ().nextBytes (bytes);
        this.secret       = new String (new Base32 ().encode (bytes));
        return this;
    }

    public String getSecret () {
        return secret;
    }

    public TotpData issuer (String issuer) {
        this.issuer = issuer;
        return this;
    }

    public TotpData algorithm (Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public String getHmacAlgorithm () {
        return algorithm.getHmacAlgorithm ();
    }

    public TotpData digits (int digits) {
        this.digits = digits;
        return this;
    }

    public int getDigits () {
        return digits;
    }

    public TotpData period (int period) {
        this.period = period;
        return this;
    }

    public int getPeriod () {
        return period;
    }


    public String buildURL () {
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        return getUrlWithParameters ("totp", label, "secret",     secret,
                                                    "issuer",     issuer,
                                                    "algorithm",  algorithm.getQrcodeName (),
                                                    "digits",     String.format ("%d", digits),
                                                    "period",     String.format ("%d", period));
    }

    private static String getUrlWithParameters (String type, String label, String... parameters) {
        var  url = new StringBuilder (String.format ("otpauth://%s/%s?", url (type), url (label)));

        for (int i = 0; i < parameters.length - 1; i += 2) {
            if (i > 0)
                url.append ("&");

            url.append (String.format ("%s=%s", url (parameters[i]), url (parameters[i+1])));
        }

        System.out.println (url);

        return url.toString ();
    }

    private static String url (String text) {
        try {
            return URLEncoder.encode (text, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException ("Failed encoding URL.");
        }
    }


    /**
     *  Generate code for current time.
     */
    public String generateCode () {
        return generateCode (Instant.now ().getEpochSecond ());
    }

    /**
     *  Generate code for given time.
     */
    public String generateCode (long epoch_second) {
        return parseDigits (generate (epoch_second / getPeriod ()));
    }

    private byte[] generate (long steps) {
        try {
            byte[] bytes = new byte[8];
            long   value = steps;
            for (int i = 8; i-- > 0; value >>>= 8) {
                bytes[i] = (byte) value;
            }

            var mac = Mac.getInstance (getHmacAlgorithm ());
            mac.init (new SecretKeySpec (new Base32 ().decode (getSecret ()),
                                         getHmacAlgorithm ()));
            return mac.doFinal (bytes);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException ("Failed generating hash.", e);
        }
    }

    private String parseDigits (byte[] hash) {
        int  offset        = hash[hash.length - 1] & 0xF;
        long truncatedHash = 0;
        for (int i = 0; i < 4; i++) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= Math.pow (10, getDigits ());
        return String.format (String.format ("%%0%dd", getDigits ()), truncatedHash);
    }
}
