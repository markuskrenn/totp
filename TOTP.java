package at.mk.totp;

import java.time.Instant;
import java.util.LinkedList;

import at.mk.totp.utils.QRCode;
import at.mk.totp.utils.TotpData;


public class TOTP
{
    // Defines how many codes will be valid (e.g. network delay, code used in last second, ...)
    private static final int DISCREPANCY = 1;


    public static boolean verify (TotpData data, String code) {
        for (int i = DISCREPANCY; i >= 0; i--) {
            if (data.generateCode (Instant.now ().getEpochSecond () - i * data.getPeriod ()).equals (code))
                return true;
        }
        return false;
    }


    /**
     *  Compile: javac -cp ".:libs/*" TOTP.java utils/*.java -d classes
     *  Run:     java  -cp "classes:libs/*" at.mk.totp.TOTP CNTGC2DWVXNYNL37CHEUUSMTBX5GDK75
     */
    public static void main (String[] args) {
        var data = new TotpData ().label ("test-app@example.com")
                                  .random_secret ()
                                  .issuer ("TEST APP");

        if (args.length == 1)
            data.secret (args[0]);
        else {
            System.out.printf ("New secret: %s\n", data.getSecret ());
            QRCode.generate (data);
        }

        loop (data);
    }

    private static void loop (TotpData data) {
        // By name one-time-passwords are only the first time valid!
        var last_used = new LinkedList <String> () {
            @Override
            public boolean add (String object) {
                if (this.size () == DISCREPANCY+1)
                    super.remove ();
                return super.add (object);
            }
        };

        while (true) {
            System.out.print ("Code: ");
            var code = System.console ().readLine ();

            if ("x".equals (code))
                return;

            if (verify (data, code) && !last_used.contains (code)) {
                System.out.println ("CORRECT");
                last_used.add (code);
                // System.out.printf ("Last codes: %s\n", last_used);
            }
            else
                System.out.println ("!!! NOT CORRECT !!!");
        }
    }
}
