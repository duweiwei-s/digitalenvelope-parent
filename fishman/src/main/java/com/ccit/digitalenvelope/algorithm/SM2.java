package com.ccit.digitalenvelope.algorithm;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import fisher.man.util.encoders.Base64;



/**
 *
 * @author ccit
 *
 */
public class SM2 {


    KeyPair kp = null;// 内部密钥时使用的临时密钥对象

    public SM2() {
        try {
            // Security.addProvider(new FishermanJCE());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2",
                    "FishermanJCE");
            kpg.initialize(256);
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            System.out.println("generate tmp SM2 keypair error");
            e.printStackTrace();
        }
    }

    /**
     * 外部公钥加密
     *
     * @param algtype
     *            :加密算法
     * @param uiAlgID
     *            ：
     * @param pubkey
     *            ：公钥（Base64）
     * @param data
     *            : 待加密的数据
     * @return 密文（Base64）
     * @throws SecurityException
     * @throws
     *
     */
    public byte[] externalPublicKeyEnc(String algtype, String uiAlgID,
                                       PublicKey pubkey, byte[] data) throws SecurityException
             {

        if (data == null) {
            throw new SecurityException("data is null");
        }
        byte[] ret = null;
        try {
//            PublicKey pubkey1 = getPublicKeyFormByteArray(Base64.decode(pubkey));
            Cipher cipher = Cipher.getInstance("SM2/2/ZeroBytePadding",
                    "FishermanJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            ret = cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("external sm2 enc error");
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 外部ECC私钥解密
     *
     * @param algtype
     *            算法类型
     * @param uiAlgID
     *            椭圆曲线参数
     * @param prikey
     * @param data
     * @return
     */
    public byte[] externalPrivateKeyDec(String algtype, String uiAlgID,
                                        PrivateKey prikey, byte[] data) {
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("SM2/1/ZeroBytePadding",
                    "FishermanJCE");
            cipher.init(Cipher.DECRYPT_MODE, prikey);
            ret = cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("external sm2 dec error");
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 内部ECC公钥加密
     *
     * @param algtype
     *            算法类型
     * @param uiAlgID
     *            椭圆曲线参数
     * @param keyno
     * @param keysize
     * @param data
     * @return
     */
    public byte[] internalPublicKeyEnc(String algtype, String uiAlgID,
                                       String keyno, int keysize, byte[] data) {
        String keyid = "RandomSM2PubKey";
        keyid += keyno;
        byte[] ret;
        PublicKey pubkey = kp.getPublic();
        try {
            SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
            Cipher cipher = Cipher.getInstance("SM2/2/ZeroBytePadding",
                    "FishermanJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pubkey, ran);// 公钥参数不起实际作用，由ran来确定密钥号。
            ret = cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("internal SM2 Enc error");
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
        String keyid = "RandomSM2PubKey";
        keyid += keyno;
        byte[] ret;
        PrivateKey prikey = kp.getPrivate();
        try {
            SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
            Cipher cipher = Cipher.getInstance("SM2/1/ZeroBytePadding",
                    "FishermanJCE");
            cipher.init(Cipher.DECRYPT_MODE, prikey, ran);// 私钥参数不起实际作用，由ran来确定密钥号。
            ret = cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("internal SM2 Dec error");
            e.printStackTrace();
            return null;
        }
        return ret;
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
            Signature sg = Signature.getInstance("SM3withSM2", "FishermanJCE");
            sg.initSign(prikey);
            sg.update(data);
            ret = sg.sign();
        } catch (Exception e) {
            System.out.println("external sm2 sign error");
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
            Signature sg = Signature.getInstance("SM3withSM2", "FishermanJCE");
            sg.initVerify(pubkey1);
            sg.update(indata);
            if (sg.verify(signdata)) {
                rv = true;
            } else {
                rv = false;
            }
        } catch (Exception e) {
            System.out.println("external sm2 verify error");
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
        byte[] ret = null;
        String keyid = "RandomSM2PubKey";
        keyid = keyid + keyno;

        PrivateKey prikey = kp.getPrivate();
        try {
            SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
            Signature sg = Signature.getInstance("SM3withSM2", "FishermanJCE");
            sg.initSign(prikey, ran);// 私钥参数不起实际作用，由ran来确定密钥号。
            sg.update(data);
            ret = sg.sign();
        } catch (Exception e) {
            System.out.println("internal sm2 sign error");
            e.printStackTrace();
            return null;
        }
        return ret;
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
        String keyid = "RandomSM2PubKey";// 该表示不生成内部RSA密钥对，可以使用该标识导出已存在的设备内部RSA公钥。
        keyid = keyid + keyno;
        try {
            SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2",
                    "FishermanJCE");
            kpg.initialize(256, ran);
            KeyPair kpin = kpg.generateKeyPair();// 导出设备内部已存在的sm2公钥。

            System.out.println("公钥 = "+new String(Base64.encode(kpin.getPublic().getEncoded())));
            Signature sg = Signature.getInstance("SM3withSM2", "FishermanJCE");
            sg.initVerify(kpin.getPublic());
            sg.update(data);
            if (sg.verify(signData)) {
                rv = true;
            } else {
                rv = false;
            }
        } catch (Exception e) {
            System.out.println("internal sm2 verify error");
            e.printStackTrace();
            return false;
        }
        return rv;
    }

    public static void main(String[] args) {
        SM2 aa = new SM2();
        aa.internalVerify("","","2",256,"".getBytes(),"".getBytes());
    }

    public String getPublicKey(String type, String keyno, int size) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * 将公钥字节数组转换为PublicKey
     */
    public PublicKey getPublicKeyFormByteArray(byte[] pubkey) {
        PublicKey key = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("SM2");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubkey);
            key = kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return key;
    }



    public byte[] sealEnvelop(String contentEncryptionAlgorithm,
                              PublicKey pubkey, byte[] indata, String keyno, int size) {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] openEnvelop(PrivateKey prikey, byte[] envelopData) {
        // TODO Auto-generated method stub
        return null;
    }



    public byte[] externalPrivateKeyDec(String algtype, String uiAlgID,
                                        byte[] prikey, byte[] data) {

        byte[] ret = null;
        try{
            PrivateKey skey = getPrivateKeyFormByteArray(prikey);
            Cipher cipher = Cipher.getInstance("SM2/1/ZeroBytePadding", "FishermanJCE");
            cipher.init(Cipher.DECRYPT_MODE, skey);
            ret = cipher.doFinal(data);
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    public byte[] externalSign(String algtype, String uiAlgID, byte[] prikey,
                               byte[] data) throws   SecurityException {

        byte[] ret = null;

        try {
            PrivateKey skey = getPrivateKeyFormByteArray(prikey);
            Signature sg = Signature.getInstance("SM3withSM2", "FishermanJCE");
            sg.initSign(skey);
            sg.update(data);
            ret = sg.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return ret;
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

}
