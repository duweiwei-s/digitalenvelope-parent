package com.ccit.digitalenvelope.asn1structure;
import java.io.File;
import java.io.FileOutputStream;






/**
 *@description DER coding for SM2 PrivateKey
 * @version 1.0
 * @author xl
 *
 */


public class SM2PrivateKeyDer
{
	/**
	 * @description encode SM2 PrivateKey
	 * @param pubKey_XY
	 * 		[in]SM2 PublicKey_XY, should be 64 bytes
	 * @param priKey
	 * 		[in]SM2 PrivateKey, should be 32 bytes
	 * @return DER format of SM2PrivateKey
	 */
	public static byte[] sm2PrivateKeyDerEncode(byte[] pubKey_XY,byte[] priKey)
	{
//		byte[] ECPrivateKey=new byte[121];
		byte[] version={0x02,0x01,0x01};
//		byte[] privateKey=new byte[34];
		byte[] parameters={0x06,0x08,0x2a,(byte)0x81,0x1c,(byte)0xcf,0x55,0x01,(byte)0x82,0x2d};
		byte[] publicKey=new byte[68];

		int n=0;
		if(priKey[0]<0)
		{
			n=35;


		}else{
			n=34;
		}
		byte[] privateKey=new byte[n];
		byte[] ECPrivateKey=new byte[87+n];
		if(n==34){
			privateKey[0]=0x02;
			privateKey[1]=0x20;
			System.arraycopy(priKey, 0, privateKey, 2, 32);
		}else{
			privateKey[0]=0x02;
			privateKey[1]=0x21;
			privateKey[2]=0x00;
			System.arraycopy(priKey, 0, privateKey, 3, 32);
		}
		publicKey[0]=0x03;
		publicKey[1]=0x42;
		publicKey[2]=0x00;
		publicKey[3]=0x04;
		System.arraycopy(pubKey_XY, 0, publicKey, 4, 64);

		ECPrivateKey[0]=0x30;
//		ECPrivateKey[1]=0x77;
		if(n==35)
		{
			ECPrivateKey[1]=0x78;
		}else
		{
			ECPrivateKey[1]=0x77;
		}
		System.arraycopy(version, 0, ECPrivateKey, 2, 3);
		System.arraycopy(privateKey, 0, ECPrivateKey, 5, n);
		ECPrivateKey[n+5]=(byte)0xa0;
		ECPrivateKey[n+6]=0x0a;
		System.arraycopy(parameters, 0, ECPrivateKey, n+7, 10);
		ECPrivateKey[n+17]=(byte)0xa1;
		ECPrivateKey[n+18]=0x44;
		System.arraycopy(publicKey, 0, ECPrivateKey, n+19, 68);

		return ECPrivateKey;
	}

	/**
	 * @description decode SM2 PrivateKeyDer
	 * @param ECPrivateKeyDer
	 * 		[in]DER format of SM2PrivateKey
	 * @return SM2 PrivateKey ,should be 32bytes
	 */
	public static byte[] sm2PrivateKeyDerDecode(byte[] ECPrivateKeyDer)
	{
		byte[] SM2PrivateKey=new byte[32];
		if(ECPrivateKeyDer.length==121){
			System.arraycopy(ECPrivateKeyDer, 7, SM2PrivateKey,0, 32);
		}else{
			System.arraycopy(ECPrivateKeyDer, 8, SM2PrivateKey,0, 32);
		}
		return SM2PrivateKey;
	}

	public static void testWrite(byte[] byte_ECPrivateKey,String Filename)throws Exception
	{
		FileOutputStream out = new FileOutputStream(new File(Filename));
		out.write(byte_ECPrivateKey);
		out.close();
	}


}
