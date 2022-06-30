package com.ccit.digitalenvelope.algorithm;

import com.zayk.jce.provider.ZAYKJceGlobal;
import com.zayk.jce.symmetric.ZAYKCryptoApi;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SM4 {

    byte[] key = null;
    public SM4(){
        try{
            //key = ZAYKCryptoApi.GenSymKey(1, 16);
        }catch (Exception e){
            e.printStackTrace();
        }

    }
    /**
     * 内部对称秘钥解密
     * @return
     */
    public byte[] internalSM4Dec(String keyId, byte[] indata){
        byte[] ret = null;
        try{
            ret= ZAYKCryptoApi.SymDec(Integer.parseInt(keyId), key, null, ZAYKJceGlobal.SGD_SMS4_ECB, indata);
            ret = pkcs5unpadding(ret);
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 内部对称秘钥加密
     * @return
     */
    public byte[] internalSM4Enc(String keyId, byte[] indata){
        byte[] ret = null;
        try{
            ret= ZAYKCryptoApi.SymEnc(Integer.parseInt(keyId), key, null, ZAYKJceGlobal.SGD_SMS4_ECB, pkcs5padding(indata));
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
        return ret;
    }

    /**
     * 生成对称密钥
     *
     * @param length
     * @return
     * @throws SecurityException
     */
    public byte[] getSecretKey(int length) throws SecurityException {
        try{
            SecureRandom random = new SecureRandom();
            // 128 bits are converted to 16 bytes;
            byte[] bytes = new byte[length/8];
            random.nextBytes(bytes);
            SecretKey key = new SecretKeySpec(bytes, "SM4");
            return key.getEncoded();
        }catch(Exception e){
            System.out.println("gen SM4 key fail");
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ECB填充模式加密
     * @param inData
     * @param key
     * @return
     * @throws 
     * @throws SecurityException
     */
    public byte[] cryptionEcbPadding(byte[] inData, byte[] key)
            throws  SecurityException {
        try {
            SecretKey key2 = new SecretKeySpec(key, "SM4");

            AlgorithmParameterSpec params = new IvParameterSpec("1111222211112222".getBytes()); //设置对称运算IV值

            Cipher cie = Cipher.getInstance("SM4/ECB/PKCS5Padding", "ZAYKProvider");

            cie.init(Cipher.ENCRYPT_MODE, key2, params,new SecureRandom());

            return cie.doFinal(inData);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] cryptionEcbNoPadding(byte[] inData, byte[] key)
            throws   SecurityException {
        try {
            SecretKey key2 = new SecretKeySpec(key, "SM4");

            AlgorithmParameterSpec params = new IvParameterSpec("1111222211112222".getBytes()); //设置对称运算IV值

            Cipher cie = Cipher.getInstance("SM4/ECB/NOPadding", "ZAYKProvider");

            cie.init(Cipher.ENCRYPT_MODE, key2, params,new SecureRandom());

            return cie.doFinal(inData);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] cryptionCbcPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        try {
            SecretKey key2 = new SecretKeySpec(key, "SM4");

            AlgorithmParameterSpec params = new IvParameterSpec("1111222211112222".getBytes()); //设置对称运算IV值

            Cipher cie = Cipher.getInstance("SM4/CBC/PKCS5Padding", "ZAYKProvider");

            cie.init(Cipher.ENCRYPT_MODE, key2, params,new SecureRandom());

            byte[] conts = cie.doFinal(inData);

            return conts;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] cryptionCbcNoPadding(byte[] inData, byte[] key,
                                       byte[] parameter) throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] cryptionCfbPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] cryptionCfbNoPadding(byte[] inData, byte[] key,
                                       byte[] parameter) throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] cryptionOfbPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] cryptionOfbNoPadding(byte[] inData, byte[] key,
                                       byte[] parameter) throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] decryptEcbPadding(byte[] inData, byte[] key)
            throws   SecurityException {
        try {
            SecretKey key2 = new SecretKeySpec(key, "SM4");

            AlgorithmParameterSpec params = new IvParameterSpec("1111222211112222".getBytes()); //设置对称运算IV值

            Cipher cie = Cipher.getInstance("SM4/ECB/PKCS5Padding", "ZAYKProvider");

            cie.init(Cipher.DECRYPT_MODE, key2, params,new SecureRandom());

            byte[] conts = cie.doFinal(inData);

            return conts;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decryptEcbNoPadding(byte[] inData, byte[] key)
            throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] decryptCbcPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        try {
            SecretKey key2 = new SecretKeySpec(key, "SM4");

            AlgorithmParameterSpec params = new IvParameterSpec("1111222211112222".getBytes()); //设置对称运算IV值

            Cipher cie = Cipher.getInstance("SM4/CBC/PKCS5Padding", "ZAYKProvider");

            cie.init(Cipher.DECRYPT_MODE, key2, params,new SecureRandom());

            byte[] conts = cie.doFinal(inData);

            return conts;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decryptCbcNoPadding(byte[] inData, byte[] key,
                                      byte[] parameter) throws   SecurityException {
        byte[] data = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/CBC/NOPADDING", "ZAYKProvider");
            ivspe = new IvParameterSpec(parameter, 0, 16);
            cp.init(Cipher.DECRYPT_MODE, sm4key, ivspe);
            data = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
        byte[] ret = null;
        if(tail != null){
            ret = new byte[data.length+tail.length];
            System.arraycopy(data, 0, ret, 0, data.length);
            System.arraycopy(tail, 0, ret, data.length, tail.length);
        }else{
            ret = new byte[data.length];
            System.arraycopy(data, 0, ret, 0, data.length);
        }
        return ret;
    }

    public byte[] decryptCfbPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] decryptCfbNoPadding(byte[] inData, byte[] key,
                                      byte[] parameter) throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] decryptOfbPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] decryptOfbNoPadding(byte[] inData, byte[] key,
                                      byte[] parameter) throws   SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public SecretKey ExportInternalKey(int keyid) throws  
            SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public static int getKeysize(String algorithm){
        int keySize = 16;
        if ("DES".equals(algorithm)){
            keySize = 8;
        }
        if ("DESede".equals(algorithm)){
            keySize = 24;
        }
        if ("SM1".equals(algorithm)){
            keySize = 16;
        }
        if ("SM4".equals(algorithm)){
            keySize = 16;
        }
        if ("AES".equals(algorithm)){
            keySize = 16;
        }
        return keySize;
    }

    public byte[] pkcs5padding(byte[] in) {
        int i = in.length;
        int j = i % 16;
        int l = i / 16;
        int k;
        if (j == 0) {
            k = i + 16;
        } else {
            k = i + 16 - j;
        }

        byte[] in_pkcs5padding = new byte[k];
        System.arraycopy(in, 0, in_pkcs5padding, 0, in.length);

        for(int m = l * 16 + j; m < l * 16 + 16; ++m) {
            in_pkcs5padding[m] = (byte)(16 - j);
        }

        return in_pkcs5padding;
    }

    public byte[] pkcs5unpadding(byte[] in) {
        int i = in[in.length - 1];
        int j = 16 - i;
        int k = (in.length - i) / 16;
        byte[] in_pkcs5unpadding = new byte[k * 16 + j];
        System.arraycopy(in, 0, in_pkcs5unpadding, 0, in_pkcs5unpadding.length);
        return in_pkcs5unpadding;
    }

}
