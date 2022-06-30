package com.ccit.digitalenvelope.algorithm;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import fisher.man.util.encoders.Base64;


public class SM4 {


    SecretKey key = null;
    public SM4(){
        try{
            KeyGenerator skg = KeyGenerator.getInstance("SM4", "FishermanJCE");
            skg.init(128);
            key = skg.generateKey();
        }catch (Exception e){
            System.out.println("gen SM4 key fail");
            e.printStackTrace();
        }

    }



    /**
     * 内部对称秘钥解密
     * @return
     */
    public byte[] internalSM4Dec(String keyId, byte[] indata){
        String alg = "SM4/ECB/PKCS5PADDING";
        byte[] data = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        String sysran = "RandomSM4" + keyId;
        try{
            SecureRandom ran = SecureRandom.getInstance(sysran, "FishermanJCE");
            Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
            cp.init(Cipher.DECRYPT_MODE, key, ran);
            data = cp.update(indata);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println(alg+" internal dec error");
            e.printStackTrace();
            return null;
        }
        byte[] ret = null;
        if(tail != null){
            if(data != null){
                ret = new byte[data.length+tail.length];
                System.arraycopy(data, 0, ret, 0, data.length);
                System.arraycopy(tail, 0, ret, data.length, tail.length);
            }else{
                ret = new byte[tail.length];
                System.arraycopy(tail, 0, ret, 0, tail.length);
            }
        }else{
            ret = new byte[data.length];
            System.arraycopy(data, 0, ret, 0, data.length);
        }
        return ret;
    }

    /**
     * 内部对称秘钥加密
     * @return
     */
    public byte[] internalSM4Enc(String keyId, byte[] indata){
        String alg = "SM4/ECB/PKCS5PADDING";
        byte[] cipherdata = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        String sysalg = "RandomSM4" + keyId;
        try{
            SecureRandom ran = SecureRandom.getInstance(sysalg, "FishermanJCE");
            Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
            cp.init(Cipher.ENCRYPT_MODE, key, ran);
            cipherdata = cp.update(indata);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println(alg+" internal enc error");
            e.printStackTrace();
            return null;
        }

        byte[] ret = null;
        if(tail != null){
            if(cipherdata == null){
                ret = new byte[tail.length];
                System.arraycopy(tail, 0, ret, 0, tail.length);
            } else {
                ret = new byte[cipherdata.length+tail.length];
                System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
                System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
            }
        }else{
            ret = new byte[cipherdata.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
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
            KeyGenerator skg = KeyGenerator.getInstance("SM4", "FishermanJCE");
            skg.init(length);
            SecretKey key = skg.generateKey();
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
        byte[] cipherdata = null;
        byte[] tail = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/ECB/PKCS5PADDING", "FishermanJCE");
            cp.init(Cipher.ENCRYPT_MODE, sm4key);
            cipherdata = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/ECB/PKCS5PADDING"+" enc error");
            e.printStackTrace();
            return null;
        }
        byte[] ret = null;
        if(tail != null){
            ret = new byte[cipherdata.length+tail.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
            System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
        }else{
            ret = new byte[cipherdata.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
        }
        return ret;
    }

    public byte[] cryptionEcbNoPadding(byte[] inData, byte[] key)
            throws   SecurityException {
        byte[] cipherdata = null;
        byte[] tail = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/ECB/NOPADDING", "FishermanJCE");
            cp.init(Cipher.ENCRYPT_MODE, sm4key);
            cipherdata = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/ECB/NOPADDING"+" enc error");
            e.printStackTrace();
            return null;
        }
        byte[] ret = null;
        if(tail != null){
            ret = new byte[cipherdata.length+tail.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
            System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
        }else{
            ret = new byte[cipherdata.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
        }
        return ret;
    }

    public byte[] cryptionCbcPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        byte[] cipherdata = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/CBC/PKCS5PADDING", "FishermanJCE");
            ivspe = new IvParameterSpec(parameter, 0, 16);
            cp.init(Cipher.ENCRYPT_MODE, sm4key, ivspe);
            cipherdata = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/CBC/PKCS5PADDING"+" enc error");
            e.printStackTrace();
            return null;
        }
        byte[] ret = null;
        if(tail != null){
            ret = new byte[cipherdata.length+tail.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
            System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
        }else{
            ret = new byte[cipherdata.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
        }
        return ret;
    }

    public byte[] cryptionCbcNoPadding(byte[] inData, byte[] key,
                                       byte[] parameter) throws   SecurityException {
        byte[] cipherdata = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/CBC/NOPADDING", "FishermanJCE");
            ivspe = new IvParameterSpec(parameter, 0, 16);
            cp.init(Cipher.ENCRYPT_MODE, sm4key, ivspe);
            cipherdata = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/CBC/NOPADDING"+" enc error");
            e.printStackTrace();
            return null;
        }
        byte[] ret = null;
        if(tail != null){
            ret = new byte[cipherdata.length+tail.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
            System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
        }else{
            ret = new byte[cipherdata.length];
            System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
        }
        return ret;
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
        byte[] data = null;
        byte[] tail = null;
        try{
            System.out.println("SM4密文数据 = "+new String(Base64.encode(inData)));
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/ECB/PKCS5PADDING", "FishermanJCE");
            cp.init(Cipher.DECRYPT_MODE, sm4key);
            data = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/ECB/PKCS5PADDING"+" dec error");
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

    public byte[] decryptEcbNoPadding(byte[] inData, byte[] key)
            throws   SecurityException {
        byte[] data = null;
        byte[] tail = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/ECB/NOPADDING", "FishermanJCE");
            cp.init(Cipher.DECRYPT_MODE, sm4key);
            data = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/ECB/NOPADDING"+" dec error");
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

    public byte[] decryptCbcPadding(byte[] inData, byte[] key, byte[] parameter)
            throws   SecurityException {
        byte[] data = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/CBC/PKCS5PADDING", "FishermanJCE");
            ivspe = new IvParameterSpec(parameter, 0, 16);
            cp.init(Cipher.DECRYPT_MODE, sm4key, ivspe);
            data = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/CBC/PKCS5PADDING"+" dec error");
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

    public byte[] decryptCbcNoPadding(byte[] inData, byte[] key,
                                      byte[] parameter) throws   SecurityException {
        byte[] data = null;
        byte[] tail = null;
        IvParameterSpec ivspe = null;
        try{
            SecretKey sm4key = new SecretKeySpec(key, "SM4");
            Cipher cp = Cipher.getInstance("SM4/CBC/NOPADDING", "FishermanJCE");
            ivspe = new IvParameterSpec(parameter, 0, 16);
            cp.init(Cipher.DECRYPT_MODE, sm4key, ivspe);
            data = cp.update(inData);
            tail = cp.doFinal();
        }catch(Exception e){
            System.out.println("SM4/CBC/NOPADDING"+" dec error");
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
        SecretKey sm1key = null;
        String keyalg = "RandomSM4InnerKey"+keyid;
        try {
            SecureRandom ran = SecureRandom.getInstance(keyalg, "FishermanJCE");
            KeyGenerator skg = KeyGenerator.getInstance("SM4", "FishermanJCE");
            skg.init(128, ran);
            sm1key = skg.generateKey();
        } catch (Exception e) {
            System.out.println("export SM1 key fail,keynum is "+keyid);
            e.printStackTrace();
        }
        return sm1key;
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

}
