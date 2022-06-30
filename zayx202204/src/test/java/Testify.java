
import com.zayk.jce.sm2.SM2PublicKey;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Testify {

    public static void main(String[] args) {
        byte[] pubkey = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEA4qzm+RnXwh5pU8s1Oiii0aHjajrhUMkkO6UZztEsGbxjiU3hHqKRoxslpMwGoAND0/XDTf4OUiVRPn/oXFW9w==");
        String originalText = "Anzxlwsw5mRdJ55JFBYF";
        String signl = "MEQCIHPbSKbGYAl05hbjA0UoCyViJCLT4V4vRrSkAxK+z3o2AiAwm748VKB09hnraXe9aHnsbvty9YtDF+ewY3HdphWHdg==";
        byte[] signdata = Base64.getDecoder().decode(signl);
        //原文
        byte[] data = originalText.getBytes();
        PublicKey pubkey1 = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubkey);
            byte[] pubEncode = spec.getEncoded();
            byte[] x = new byte[64];
            byte[] y = new byte[64];
            System.arraycopy(pubEncode, pubEncode.length - 64, x, 32, 32);
            System.arraycopy(pubEncode, pubEncode.length - 32, y, 32, 32);
            pubkey1 =  new SM2PublicKey(x, y);
        } catch (Exception e) {
            e.printStackTrace();
        }

        boolean rv = false;
        try {

            Signature sg = Signature.getInstance("SM3/SM2", "ZAYKProvider");
            sg.initVerify(pubkey1);
            sg.update(data);
            if (sg.verify(signdata)) {
                rv = true;
            } else {
                rv = false;
            }
            System.out.println(rv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
