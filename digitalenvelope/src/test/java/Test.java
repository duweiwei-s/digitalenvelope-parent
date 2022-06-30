


import com.ccit.digitalenvelope.algorithm.SM2;
import com.ccit.digitalenvelope.asn1structure.CERT_INFO;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, IOException {
        String cert = "MIIBxzCCAXSgAwIBAgIEAqx4hzAKBggqgRzPVQGDdTA5MQswCQYDVQQGEwJDTjEqMCgGA1UEAwwh56e75Yqo5LqS6IGU572R5a6J5YWo5pyN5Yqh5bmz5Y+wMB4XDTIyMDQwMjA4MTcxNloXDTIzMDQwMjA4MTcxNlowLjELMAkGA1UEBhMCQ04xHzAdBgNVBAMMFjIwMjEwNTIwMTQyNjEwODE1NTA5MTAwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATaGOxgmkMngJN3IJFuK8QHsvFd+aUCk4eIlEZrpr7RycgSzFPIy9yhv7YA+LH7JoO6elTzXTLiROnNonAZPxPvo3UwczBkBgNVHQ4EXQRbMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2hjsYJpDJ4CTdyCRbivEB7LxXfmlApOHiJRGa6a+0cnIEsxTyMvcob+2APix+yaDunpU810y4kTpzaJwGT8T7zALBgNVHQ8EBAMCBsAwCgYIKoEcz1UBg3UDQQDcFmAENK0UO40ZOpZxb+BzSRaXsEKNzh9LTdYn7xnaUvePgR4lGnb7IjZGfEBN0IrExNaqKFj7V/3gy36YOaxs";
        CERT_INFO certinfo  = new CERT_INFO(Base64.decode(cert));
        SM2 sm2 = new SM2();
        PublicKey pubkey = sm2.getPublicKeyFormByteArray(certinfo.getPublicKey());

        System.out.println(byteToHex(pubkey.getEncoded()));
        KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2", "ZAYKProvider");
        pg.initialize(1, new SecureRandom());
        KeyPair kpg = pg.genKeyPair();
        System.out.println(byteToHex(kpg.getPublic().getEncoded()));
        byte[] pk = kpg.getPublic().getEncoded();
        byte[] xy = getPublicKeyFormByteArray2(pk);
        System.out.println("======   "+byteToHex(xy));
//        pubkey = kpg.getPublic();
        Cipher cipher = Cipher.getInstance("SM2/ECB/Raw",
                "ZAYKProvider");
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        byte[] ret = cipher.doFinal("12345678".getBytes(StandardCharsets.UTF_8));
        System.out.println(byteToHex(ret));

//        byte[] retder = zaykToCCITDerencodable(ret).getEncoded();
//        byte[] retdder = Objects.requireNonNull(ccitToZAYKDerencodable(retder)).getEncoded();
        System.out.println(byteToHex(kpg.getPrivate().getEncoded()));
        cipher.init(Cipher.DECRYPT_MODE,kpg.getPrivate());
        byte[] data = cipher.doFinal(ret);
        System.out.println(new String(data));


    }

    /**
     *
     * 加密时调用
     *
     * */
    public static DERSequence zaykToCCITDerencodable(byte[] data) throws IOException {
        ASN1EncodableVector encodableVector = new ASN1EncodableVector();

        //插入integer
//    	BigIntegers.asUnsignedByteArray()
        //获取实例对象
        ASN1InputStream ais1 = new ASN1InputStream(new ByteArrayInputStream(data));
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(ais1.readObject());

        ASN1Encodable objectAt = asn1Sequence.getObjectAt(0);//根据下标获取sequence值
        ASN1OctetString asn1OctetString = ASN1OctetString.getInstance(objectAt);

        ASN1Integer derInteger = new ASN1Integer(asn1OctetString.getOctets());//组成Integer
        ASN1Integer derInteger1 = new ASN1Integer(BigIntegers.asUnsignedByteArray(derInteger.getValue()));

        ASN1Encodable objectAt2 = asn1Sequence.getObjectAt(1);
        ASN1OctetString asn1OctetString2 = ASN1OctetString.getInstance(objectAt2);
        ASN1Integer derIntegerinteger = new ASN1Integer(asn1OctetString2.getOctets());
        ASN1Integer derInteger2 = new ASN1Integer(BigIntegers.asUnsignedByteArray(derIntegerinteger.getValue()));

        ASN1Encodable objectAt3 = asn1Sequence.getObjectAt(2);

        ASN1Encodable objectAt4 = asn1Sequence.getObjectAt(4);
        ASN1OctetString derOctetString2 = ASN1OctetString.getInstance(objectAt4);

        encodableVector.add(derInteger1);
        encodableVector.add(derInteger2);
        encodableVector.add(objectAt3);
        encodableVector.add(objectAt4);

        return new DERSequence(encodableVector);
    }

    /**
     * 作解密使用 / 退回原加密后格式
     *
     *
     * */
    public static DERSequence ccitToZAYKDerencodable(byte[] data){

        try{
            ASN1EncodableVector encodableVector = new ASN1EncodableVector();

            //获取实例对象
            ASN1InputStream ais1 = new ASN1InputStream(new ByteArrayInputStream(data));
            ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(ais1.readObject());

            ASN1Encodable objectAt = asn1Sequence.getObjectAt(0);
            ASN1Integer derInteger = ASN1Integer.getInstance(objectAt);

            ASN1Encodable objectAt1 = asn1Sequence.getObjectAt(1);
            ASN1Integer derInteger1 = ASN1Integer.getInstance(objectAt1);

            ASN1Encodable objectAt3 = asn1Sequence.getObjectAt(2);
            ASN1Encodable objectAt4 = asn1Sequence.getObjectAt(3);

            ASN1OctetString asn1OctetString2 = ASN1OctetString.getInstance(objectAt4);
            ASN1Integer derIntegerinteger = new ASN1Integer(asn1OctetString2.getOctets());
            int length = derIntegerinteger.getEncoded("DER").length;


            encodableVector.add(new DEROctetString(zeroFill(derInteger.getEncoded("DER"))));//组入OTCString
            encodableVector.add(new DEROctetString(zeroFill(derInteger1.getEncoded("DER"))));
            encodableVector.add(objectAt3);
            encodableVector.add(new ASN1Integer(length-2));
            encodableVector.add(objectAt4);

            DERSequence derSequence = new DERSequence(encodableVector);
            return derSequence;
        } catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }
    /**
     * 解密时转为原加密数据时补“0”调用
     *
     * */
    public static byte[] zeroFill(byte[] data){
        byte[] indata = new byte[32];
        System.arraycopy(data,2, indata, 0, 32);
        byte[] zero = new byte[32];
        byte[] zf = new byte[indata.length+zero.length];
        System.arraycopy(zero, 0, zf, 0, zero.length);
        System.arraycopy(indata, 0, zf, zero.length, indata.length);
        return zf;
    }

    /**
     * 公钥去格式并返回数组 《中安云科》 去除公钥填充
     *
     *
     *
     * */
    public static byte[] getPublicKeyFormByteArray2(byte[] pubkey){
        PublicKey key = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubkey);
            byte[] pubEncode = spec.getEncoded();
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            byte[] zf = new byte[1];
            System.arraycopy(pubEncode,7 ,zf ,0 ,1 );
            System.arraycopy(pubEncode, 41, x, 0, 32);
            System.arraycopy(pubEncode, pubEncode.length - 32, y, 0, 32);
            byte[] xy = new byte[x.length+y.length];
            System.arraycopy(x, 0, xy, 0, x.length);
            System.arraycopy(y, 0, xy, x.length, y.length);
            byte[] xyz = new byte[xy.length+zf.length];
            System.arraycopy(zf, 0, xyz, 0, zf.length);
            System.arraycopy(xy, 0, xyz, zf.length, xy.length);
            return xyz;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
    /**
     * byte数组转hex
     */
    public static String byteToHex(byte[] bytes){
        String strHex;
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            strHex = Integer.toHexString(aByte & 0xFF);
            sb.append((strHex.length() == 1) ? "0" + strHex : strHex); // 每个字节由两个字符表示，位数不够，高位补0
        }
        return sb.toString().trim();
    }

}
