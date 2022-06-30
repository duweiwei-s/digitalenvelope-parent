package com.ccit.digitalenvelope.algorithm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.Cipher;

import com.zayk.jce.sm2.SM2PublicKey;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;


/**
 * @author ccit
 */
public class SM2 {

    /**
     * 外部公钥加密
     *
     * @param algtype :加密算法
     * @param uiAlgID ：
     * @param pubkey  ：公钥（Base64）
     * @param data    : 待加密的数据
     * @return 密文（Base64）
     * @throws SecurityException
     * @throws
     */
    public byte[] externalPublicKeyEnc(String algtype, String uiAlgID,
                                       PublicKey pubkey, byte[] data) throws SecurityException {

        byte[] ret = null;
        byte[] derEncoded = null;
        try {

            Cipher cipher = Cipher.getInstance("SM2/ECB/Raw",
                    "ZAYKProvider");
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            ret = cipher.doFinal(data);
            //加密后转格式
//            derEncoded = zaykToCCITDerencodable(ret).getEncoded();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 外部ECC私钥解密
     *
     * @param algtype 算法类型
     * @param uiAlgID 椭圆曲线参数
     */
    public byte[] externalPrivateKeyDec(String algtype, String uiAlgID,
                                        PrivateKey prikey, byte[] data) {
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("SM2/ECB/Raw",
                    "ZAYKProvider");
            cipher.init(Cipher.DECRYPT_MODE, prikey);
            //解密前转格式
//            byte[] derEncoded = ccitToZAYKDerencodable(data).getEncoded("DER");
            ret = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 内部ECC公钥加密
     *
     * @param algtype 算法类型
     * @param uiAlgID 椭圆曲线参数
     * @param keyno
     * @param keysize
     * @param data
     * @return
     */
    public byte[] internalPublicKeyEnc(String algtype, String uiAlgID,
                                       String keyno, int keysize, byte[] data) {
        byte[] ret = null;
        byte[] derEncoded = null;
        try {
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2", "ZAYKProvider");
            pg.initialize(Integer.parseInt(keyno), new SecureRandom());
            KeyPair kpg = pg.genKeyPair();
            PublicKey pubkey = kpg.getPublic();
            Cipher cipher = Cipher.getInstance("SM2/ECB/Raw",
                    "ZAYKProvider");
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            ret = cipher.doFinal(data);
            //加密后转格式
//            derEncoded = zaykToCCITDerencodable(ret).getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return ret;
    }

    /**
     * 内部私钥解密
     *
     * @param algtype
     * @param uiAlgID
     * @param keyno
     * @param keysize
     * @param data
     * @return
     */
    public byte[] internalPrivateKeyDec(String algtype, String uiAlgID,
                                        String keyno, int keysize, byte[] data) {
        System.out.println("进入内部私钥解密");
        byte[] tResult = null;
        KeyPair kr = null;
        try {
            //KeyPairGenerator.getInstance(algorithm,provider)
            //参数说明：
            //algorithm：设置算法类型，国密为“SM2”。
            //provider：JCE提供者的名字，中安云科名称为“ZAYKProvider”
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2", "ZAYKProvider"); // ??----------
            //initialize(keysize,random)
            //初始化密钥对生成器
            //参数说明：
            //keysize：0：生成外部密钥，非零获取设备内的密钥
            //random：随机数（保留）。
            pg.initialize(Integer.parseInt(keyno), new SecureRandom());
            //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
            kr = pg.genKeyPair();
            //生成密钥成功。
            //通过调用对content中的内容进行加密。
            //返回值：加密后的结果。
            //定义解密Cipher类对象
            Cipher decCipher = Cipher.getInstance("SM2/ECB/Raw", "ZAYKProvider"); // ??----------
            //初始化Cipher类对象
            decCipher.init(Cipher.DECRYPT_MODE, kr.getPrivate());
            //调用解密函数
            //解密前转格式
//            byte[] derEncoded = Objects.requireNonNull(ccitToZAYKDerencodable(data)).getEncoded("DER");
            tResult = decCipher.doFinal(data);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return tResult;
    }

    /**
     * 外部私钥签名
     *
     * @param algtype
     * @param uiAlgID
     * @param prikey
     * @param data
     * @return
     */
    public byte[] externalSign(String algtype, String uiAlgID,
                               PrivateKey prikey, byte[] data) {
        byte[] ret = null;
        try {
            Signature sg = Signature.getInstance("SM3withSM2", "ZAYKProvider");
            sg.initSign(prikey);
            sg.update(data);
            ret = sg.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 外部公钥验签
     *
     * @param algtype
     * @param uiAlgID
     * @param pubkey
     * @param signdata
     * @param indata
     * @return
     * @throws
     * @throws SecurityException
     */
    public boolean externalVerify(String algtype, int uiAlgID, byte[] pubkey,
                                  byte[] signdata, byte[] indata) throws
            SecurityException {

        boolean rv = false;
        try {
            PublicKey pubkey1 = getPublicKeyFormByteArray(pubkey);
            Signature sg = Signature.getInstance("SM3/SM2", "ZAYKProvider");
            sg.initVerify(pubkey1);
            sg.update(indata);
            if (sg.verify(signdata)) {
                rv = true;
            } else {
                rv = false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return rv;
    }

    /**
     * 内部签名
     *
     * @param algtype
     * @param uiAlgID
     * @param keyno
     * @param keysize
     * @param data
     * @return
     * @throws SecurityException
     */
    public byte[] internalSign(String algtype, String uiAlgID, String keyno,
                               int keysize, byte[] data) throws SecurityException {
        byte[] sign = null;
        try {
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2", "ZAYKProvider");// ??----------
            //initialize(keysize,random)
            //初始化密钥对生成器
            //参数说明：
            //keysize：0：生成外部密钥，非零获取设备内的密钥
            pg.initialize(Integer.parseInt(keyno), new SecureRandom());
            KeyPair kp = null;
            //调用genKeyPair()函数生成密钥对，并保存到数组中，以便于后面测试中使用。
            kp = pg.genKeyPair();
            //定义签名对象
            //参数说明：
            //algorithm：签名的算法，一般格式：“SM3/SM2”
            //provider：JCE提供者的名字，一般应为：“ZAYKProvider”
            Signature tSig = Signature.getInstance("SM3/SM2", "ZAYKProvider");
            //SignedObject(object,privatekey,signingEngine)
            //定义SignedObject类的对象，对一个Object进行签名。
            //参数说明：
            //object：需要进行签名的对象。
            //privatekey：用来进行签名的私钥。
            //signingEngin：用来进行签名的引擎，应该为上面定义的Signature类的对象。
            tSig.initSign(kp.getPrivate());
            //update(content)
            //更新签名数据
            //参数说明：
            //content：需要签名的数据test obj
            tSig.update(data);
            sign = tSig.sign();
            return sign;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sign;
    }

    /**
     * 内部验签
     *
     * @param algtype
     * @param uiAlgID
     * @param keyno
     * @param keysize
     * @param data
     * @return
     */
    public boolean internalVerify(String algtype, String uiAlgID, String keyno,
                                  int keysize, byte[] data, byte[] signData) {
        boolean rv = false;
        try {
            KeyPairGenerator pg = KeyPairGenerator.getInstance("SM2", "ZAYKProvider");
            pg.initialize(Integer.valueOf(keyno), new SecureRandom());
            KeyPair kpg = pg.genKeyPair();
            PublicKey pubkey = kpg.getPublic();

            Signature sg = Signature.getInstance("SM3/SM2", "ZAYKProvider");
            sg.initVerify(pubkey);
            sg.update(data);
            if (sg.verify(signData)) {
                rv = true;
            } else {
                rv = false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return rv;
    }


    public String getPublicKey(String type, String keyno, int size) {
        // TODO 该方法没有实现
        return null;
    }

    /**
     * 将公钥字节数组转换为PublicKey 中安云科密码机使用
     */
    public PublicKey getPublicKeyFormByteArray(byte[] pubkey) {
        PublicKey key = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubkey);
            byte[] pubEncode = spec.getEncoded();
            byte[] x = new byte[64];
            byte[] y = new byte[64];
            System.arraycopy(pubEncode, pubEncode.length - 64, x, 32, 32);
            System.arraycopy(pubEncode, pubEncode.length - 32, y, 32, 32);
            return new SM2PublicKey(x, y);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public byte[] sealEnvelop(String contentEncryptionAlgorithm,
                              PublicKey pubkey, byte[] indata, String keyno, int size) {
        // TODO 该方法没有实现
        return null;
    }

    public byte[] openEnvelop(PrivateKey prikey, byte[] envelopData) {
        // TODO 该方法没有实现
        return null;
    }


    public byte[] externalPrivateKeyDec(String algtype, String uiAlgID,
                                        byte[] prikey, byte[] data) {
        // TODO 该方法没有实现
        return null;
    }

    public byte[] externalSign(String algtype, String uiAlgID, byte[] prikey,
                               byte[] data) throws SecurityException {
        // TODO 该方法没有实现
        return null;
    }

    /**
     * 将私钥字节数组转换为privatekey
     */
    public static PrivateKey getPrivateKeyFormByteArray(byte[] prikey) {
        PrivateKey key = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("SM2");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(prikey);
            key = kf.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return key;

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

}
