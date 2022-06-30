package com.ccit.digitalenvelope.algorithm;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


/**
 * <p>Title:DigestAlgorithms</p>
 *
 * <p>Description: 摘要算法实现类（软实现）</p>
 *
 * <p>Copyright: Copyright (c) 2009</p>
 *
 * <p>Company: ccit</p>
 *
 * @author sunfei
 * @version 1.0
 */
public class Hash {



    public byte[] md2Digest(byte[] data) throws SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] md5Digest(byte[] data) throws SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] sha1Digest(byte[] data) throws SecurityException {
        byte[] inBuf = new byte[256];
        byte[] result = null;
        for(int i = 0; i < inBuf.length; i++)
        {
            inBuf[i] = (byte)i;
        }
        try {
            MessageDigest dig = MessageDigest.getInstance("SHA1","FishermanJCE");
            dig.reset();
            dig.update(inBuf);
            result = dig.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public byte[] sha256Digest(byte[] data) throws SecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public byte[] sm3Digest(byte[] data) throws SecurityException {
        try {
            MessageDigest md=MessageDigest.getInstance("SM3","ZAYKProvider");
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
       return null;
    }


}
