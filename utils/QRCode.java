package at.mk.totp.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;


public class QRCode
{
    public static void generate (TotpData data) {
        System.out.printf ("QR Code:\n<img src=\"%s\"/>\n\n\n", getImageSrc (createQrcode (data.buildURL ())));
    }


    private static String getImageSrc (byte[] data) {
        return String.format("data:image/png;base64,%s", new String (Base64.getEncoder ().encode (data)));
    }

    private static byte[] createQrcode (String url) {
        try (var output = new ByteArrayOutputStream ()) {
            var bitMatrix  = new QRCodeWriter ().encode (url, BarcodeFormat.QR_CODE, 300, 300);
            MatrixToImageWriter.writeToStream (bitMatrix, "PNG", output);

            return output.toByteArray ();
        } catch (WriterException | IOException e) {
            System.err.printf ("Failed creating qrcode: %s\n", e);
            return null;
        }
    }
}
