package com.ccit.digitalenvelope.asn1structure;
import java.io.ByteArrayInputStream;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;


/**
 * @description DER coding for SM2 Cipher data 
 * @version 1.0
 * @author xl
 *
 */


public class SM2CipherDer
{



	/**
	 * @description
	 * @param derCipher
	 * 		[in]input der cipher data waiting to decode;
	 * @return der decoded cipher data,any length
	 * @throws Exception
	 */
	public static byte[] sm2CipherDerDecode(byte[] derCipher)throws Exception
	{
		ByteArrayInputStream bIn=new ByteArrayInputStream(derCipher);
		ASN1InputStream aIn=new ASN1InputStream(bIn);
		ASN1Sequence seq=(ASN1Sequence)aIn.readObject();
		aIn.close();

		ASN1Integer XCoordinate=(ASN1Integer)seq.getObjectAt(0);
		ASN1Integer YCoordinate=(ASN1Integer)seq.getObjectAt(1);
		DEROctetString HASH=(DEROctetString)seq.getObjectAt(2);
		DEROctetString ciphertext=(DEROctetString)seq.getObjectAt(3);

		BigInteger a=XCoordinate.getValue();
		byte[] C1_X=a.toByteArray();
		BigInteger b=YCoordinate.getValue();
		byte[] C1_Y=b.toByteArray();

		byte[] byte_HASH=HASH.getOctets();
		byte[] byte_ci=ciphertext.getOctets();

//		int num=0;
		byte[] SM2Cipher=new byte[64+1+32+byte_ci.length];
		SM2Cipher[0]=0x04;
		if(C1_X[0]==0x00)
		{
			System.arraycopy(C1_X, 1, SM2Cipher, 1, 32);
		}else
		{
			System.arraycopy(C1_X, 0, SM2Cipher, 1, 32);
		}
		if(C1_Y[0]==0x00)
		{
			System.arraycopy(C1_Y, 1, SM2Cipher, 33, 32);
		}else
		{
			System.arraycopy(C1_Y, 0, SM2Cipher, 33, 32);
		}
		System.arraycopy(byte_HASH, 0, SM2Cipher, 65, 32);
		System.arraycopy(byte_ci, 0, SM2Cipher, 97, byte_ci.length);
		return SM2Cipher;

	}


	public static void testWrite(byte[] byte_sm2Cipher,String Filename)throws Exception
	{
		FileOutputStream out = new FileOutputStream(new File(Filename));
		out.write(byte_sm2Cipher);
		out.close();
	}


}
