package com.ccit.digitalenvelope;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;

import com.ccit.digitalenvelope.algorithm.Hash;
import com.ccit.digitalenvelope.algorithm.SM2;
import com.ccit.digitalenvelope.algorithm.SM4;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.encoders.Base64;


import com.ccit.digitalenvelope.asn1structure.CERT_INFO;
import com.ccit.digitalenvelope.asn1structure.DERToObj;
import com.ccit.digitalenvelope.asn1structure.EncryptContentInfo;
import com.ccit.digitalenvelope.asn1structure.FileUtil;
import com.ccit.digitalenvelope.asn1structure.PKCSObjectIdentifiers;
import com.ccit.digitalenvelope.asn1structure.SignedAndEnvelopedData;
import com.ccit.digitalenvelope.exception.CCITSecurityException;
import com.ccit.digitalenvelope.exception.PKCS7Exception;


public class EnvelopeUtil {


	/**
	 *
	 * 封装数字信封(文件格式)
	 * @param recipientCert 接收者证书
	 * @param keyno 签名者证书对应密钥号
	 * @param signerCert 签名者证书
	 * @param filepath 原文件路径
	 * @return p7数据
	 */
	public String encodeEnvelopedData(String recipientCert,String keyno,String signerCert,String filepath){

		try {
			/*读取文件原文**/
			byte[] indata=FileUtil.readFileToByte(new File(filepath));
			byte[] envelopedData=makeDigitalEnvelopes(recipientCert,keyno,signerCert,indata);
			assert envelopedData != null;
			return new String(Base64.encode(envelopedData));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 *
	 * @param recipientCert 接收者证书
	 * @param keyno 签名者证书对应密钥号
	 * @param signerCert 签名者证书
	 * @param indata 签名原文
	 * @return  p7数据
	 */
	public String encodeEnvelopedData(String recipientCert,String keyno,String signerCert,byte[] indata){

		try {
			byte[] envelopedData=makeDigitalEnvelopes(recipientCert,keyno,signerCert,indata);
			assert envelopedData != null;
			return new String(Base64.encode(envelopedData));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}


	/**
	 * 解析数字信封(文件格式)
	 * @param keyno 密码机密钥号
	 * @param filepath 源文件路径
	 * @param outpath 密文文件输出路径
	 * @return 签名结果 true or false
	 */

	public boolean decodeEnvelopedData(String keyno,String filepath,String outpath){
		try {
			byte[] enveloped=FileUtil.readFileToByte(new File(filepath));
			byte[] plainData = parseDigitalEnvelopes(enveloped,keyno);
			FileUtil.writeBytesToFile(plainData, new File(outpath));
			return true;

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

	}

	/**
	 *
	 * @param keyno 密码机密钥号
	 * @param enveploped 数字信封 p7数据
	 * @return 明文，返回为GBK编码
	 */

	public String decodeEnvelopedData(String keyno,byte[] enveploped){
		try {
			byte[] plainData = parseDigitalEnvelopes(enveploped,keyno);
			assert plainData != null;
			return new String(plainData);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}
	/**
	 * @param keyno 密码机密钥号
	 * @param enveploped 数字信封 p7数据
	 * @return 明文，Byte[]类型
	 */

	public byte[] decodeEnvelopedData_byfileData(String keyno,byte[] enveploped){
		try {
			return parseDigitalEnvelopes(enveploped,keyno);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * 验签方法
	 * @param inData 原文
	 * @param signData 签名值
	 * @param cert 证书
	 */

	public boolean verifySign(byte[] inData,byte[] signData,String cert){
		//解析公钥
		CERT_INFO certInfo  = new CERT_INFO(Base64.decode(cert));
		SM2 sm2 = new SM2();
		return sm2.externalVerify("SM3/ECC", 7, certInfo.getPublicKey(), signData, inData);

	}

	/**
	 * 内部密钥签名
	 * @param keyNo 密码机密钥号
	 * @param data 签名原文
	 * @return 签名值
	 */
	public   String internalPrivateKeySign(String keyNo,byte[] data){
		SM2 sm2 = new SM2();
		byte[] signer = sm2.internalSign("","",keyNo,0,data);
		return new String(Base64.encode(signer));
	}

	/**
	 * 内部私钥解密接口
	 * @param keyNo 密码机密钥号
	 * @param data sm2密文
	 * @return 原文
	 */
	public byte[] internalPrivateKeyDec(String keyNo,byte[] data){

		SM2 sm2 = new SM2();
		byte[] text = sm2.internalPrivateKeyDec("","",keyNo,0,data);
		return text;
	}

	/**
	 * 证书加密
	 * @param  cert 证书
 	 * @param data 原文
	 * @return 密文
	 */
	public String certEnc(String cert,byte[] data) {
		//解析证书
		CERT_INFO certinfo  = new CERT_INFO(Base64.decode(cert));
		SM2 sm2 = new SM2();
		PublicKey pubkey = sm2.getPublicKeyFormByteArray(certinfo.getPublicKey());
		byte[] cipher = sm2.externalPublicKeyEnc("","",pubkey,data);
		return new String(Base64.encode(cipher));
	}

	/**
	 * sm3摘要
	 * @param data 原文数据
	 * @return 摘要值
	 */
	public byte[] sm3Digest(byte[] data){
		Hash hash = new Hash();
		return hash.sm3Digest(data);

	}

	/**
	 *  计算HMAC-SM3
	 * @param data 原文数据
	 * @param key 校验key
	 * @return hmac
	 */
	private static int BLOCK_LENGTH = 64;
	public  byte[] sm3HashMac(byte[] data, byte []key) {

		Hash hash = new Hash();
		byte[] sm3_key;
		byte[] structured_key = new byte[BLOCK_LENGTH];
		byte[] IPAD = new byte[BLOCK_LENGTH];
		byte[] OPAD = new byte[BLOCK_LENGTH];

		if (key.length> BLOCK_LENGTH) {

			sm3_key = hash.sm3Digest(key);
			System.arraycopy(sm3_key, 0, structured_key, 0, sm3_key.length);

		} else {
			System.arraycopy(key, 0, structured_key, 0, key.length);
		}
		for (int i = 0; i < BLOCK_LENGTH; i++) {
			IPAD[i] = 0x36;
			OPAD[i] = 0x5c;
		}
		byte[] ipadkey = XOR(structured_key, IPAD);
		int textLen = data.length;
		byte[] t3 = new byte[BLOCK_LENGTH + textLen];
		System.arraycopy(ipadkey, 0, t3, 0, ipadkey.length);
		System.arraycopy(data, 0, t3, ipadkey.length, textLen);

		byte[] t4 = hash.sm3Digest(t3);

		byte[] opadkey = XOR(structured_key, OPAD);
		byte[] t6 = new byte[BLOCK_LENGTH + t4.length];
		System.arraycopy(opadkey, 0, t6, 0, opadkey.length);
		System.arraycopy(t4, 0, t6, opadkey.length, t4.length);

		return (hash.sm3Digest(t6));
	}

	private static String byteArrayToHexStr(byte[] bytes) {
		String strHex;
		StringBuilder sb = new StringBuilder();
		for (byte aByte : bytes) {
			strHex = Integer.toHexString(aByte & 0xFF);
			sb.append(" ").append((strHex.length() == 1) ? "0" : "").append(strHex); // 每个字节由两个字符表示，位数不够，高位补0
		}
		return sb.toString().trim();
	}

	private static byte[] XOR(byte[] key, byte[] data) {
		if (data == null || data.length == 0 || key == null || key.length == 0) {
			return data;
		}

		byte[] result = new byte[data.length];
		for (int i = 0; i < data.length; i++) {
			result[i] = (byte) (data[i] ^ (key[i]));

		}
		System.out.println(byteArrayToHexStr(result));
		return result;
	}


	private static byte[] parseDigitalEnvelopes(byte[] enveploped, String keyno){
		ByteArrayInputStream bIn = new ByteArrayInputStream(enveploped);
		ASN1InputStream p7in = new ASN1InputStream(bIn);
		ASN1Primitive p7obj;
		try {
			p7obj = p7in.readObject();
			ContentInfo p7seq = ContentInfo.getInstance((ASN1Sequence) p7obj);
			ASN1Sequence seq = DERToObj.getASN1Sequence(p7seq.getContent().toASN1Primitive().getEncoded());
			int index = 0;
			ASN1Integer version = (ASN1Integer) seq.getObjectAt(index++);
			ASN1Set recipientInfos = ASN1Set.getInstance(seq.getObjectAt(index++));
			ASN1Set digalgSet = ASN1Set.getInstance(seq.getObjectAt(index++));
			EncryptContentInfo encryptedContentInfo = new EncryptContentInfo(
					(ASN1Sequence) seq.getObjectAt(index++));
			DERTaggedObject der = (DERTaggedObject) seq.getObjectAt(index++);
			ASN1Sequence certSet = ASN1Sequence.getInstance(der.getObject());
			ASN1Set signerInfoSet = ASN1Set.getInstance(seq
					.getObjectAt(index++));
			// 解析EncryptedContentInfo
			ASN1OctetString encryptedContent = encryptedContentInfo
					.getEncryptedContent();
			AlgorithmIdentifier algOfENC = encryptedContentInfo
					.getContentEncryptionAlgorithm();
			KeyTransRecipientInfo ktri = null;
			// 解析RecipientInfos
			for (int i = 0; i < recipientInfos.size()
					&& recipientInfos.getObjectAt(i) != null; i++) {
				RecipientInfo rinfo = new RecipientInfo((ASN1Primitive) recipientInfos.getObjectAt(i));
				ktri = KeyTransRecipientInfo.getInstance(rinfo.getInfo());

			}
			ASN1OctetString encryptedKey = ktri.getEncryptedKey();
			System.out.println(new String(Base64.encode(encryptedKey.getOctets())));
			// 解密对称密钥
			SM2 sm2 = new SM2();
			byte[] symmKey = sm2.internalPrivateKeyDec("ECC/ECB/PKCS1Padding", "7", keyno,0, encryptedKey.getOctets());
			//对称解密
			SM4 sm4 = new SM4();
			return sm4.decryptEcbPadding(encryptedContent.getOctets(), symmKey);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;

	}

	private byte[] makeDigitalEnvelopes(String recipientCert,String keyno,String signerCert,byte[] indata) throws Exception {
		/** 数字信封版本号，默认为1 */
		ASN1Integer version = new ASN1Integer(1);
		SM4 sm4 = new SM4();
		/**生成对称密钥**/
		byte[] symkey = sm4.getSecretKey(128);
		/** 接收者信息*/
		ASN1Set recipientInfos = createRecipientInfos(recipientCert, symkey);
		/** 摘要算法标识 **/
		AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.SM3,null);
		ASN1Set digestAlgorithms = new DERSet(digestAlgorithmIdentifier);
		/** 加密后的内容信息 */
		EncryptedContentInfo encryptedContentInfo;
		try {
			encryptedContentInfo = createEncryptedContentInfo(indata, symkey);
			/** 签名者证书 */
			X509CertificateStructure signerCertStruct = DERToObj.getX509CertStructureFromDer(Base64.decode(signerCert));
			ASN1Set certificates = new DERSet(signerCertStruct);
			/** 签名者信息 */
			SignerInfo signerInfo = getSignerInfo(encryptedContentInfo,signerCert,keyno,indata);
			ASN1Set signerInfos = new DERSet(signerInfo);
			SignedAndEnvelopedData ret = new SignedAndEnvelopedData(version, recipientInfos,digestAlgorithms, encryptedContentInfo, certificates, null,signerInfos);
			ContentInfo con =new ContentInfo(PKCSObjectIdentifiers.SIGNEDANDENVELOPEDDATA,ret);
			return con.toASN1Primitive().getEncoded("DER");
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}





	/**
	 * 接受者信息
	 *
	 * <pre>
	 * KeyTransRecipientInfo ::= SEQUENCE {
	 *     version CMSVersion,
	 *     issuerAndSerialNumber IssuerAndSerialNumber,
	 *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	 *     encryptedKey EncryptedKey
	 * }
	 * </pre>
	 */
	private ASN1Set createRecipientInfos(String recipientCert,byte[] key) throws Exception{
		try {
			X509CertificateStructure signerCertStruct = DERToObj.getX509CertStructureFromDer(Base64.decode(recipientCert));
			CERT_INFO certinfo  = new CERT_INFO(Base64.decode(recipientCert));

			IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(signerCertStruct.getIssuer(),signerCertStruct.getSerialNumber().getValue());
			AlgorithmIdentifier keyEncryptionAlgorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.2.1"),PKCSObjectIdentifiers.SM3WithSM2Encryption);
			SM2 sm2 = new SM2();
			PublicKey pubkey = sm2.getPublicKeyFormByteArray(certinfo.getPublicKey());
			byte[] encryptedKey =sm2.externalPublicKeyEnc("ECC/ECB/PKCS1Padding", "256",pubkey , key);
			KeyTransRecipientInfo keyTransRecipientInfo = new KeyTransRecipientInfo(new RecipientIdentifier(issuerAndSerialNumber),keyEncryptionAlgorithmIdentifier, new DEROctetString(encryptedKey));
			DERSet recipientInfos = new DERSet(new RecipientInfo(keyTransRecipientInfo));
			return recipientInfos;
		} catch (CCITSecurityException e) {
			e.printStackTrace();
			return null;
		}




	}

	/**
	 * 加密内容
	 *
	 * <pre>
	 * EncryptedContentInfo ::= SEQUENCE {
	 *     contentType ContentType,
	 *     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
	 *     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	 * }
	 * </pre>
	 * @throws Exception
	 *
	 */
	private EncryptedContentInfo createEncryptedContentInfo(byte[] indata,byte[] secretkey)throws Exception {
		EncryptedContentInfo ret = null;
		try {
			AlgorithmIdentifier contentEncryptionAlgorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.SM4_ECB);
			SM4 sm4 = new SM4();
			//对称加密
			byte[] conts=sm4.cryptionEcbPadding(indata, secretkey);
			ret = new EncryptedContentInfo(PKCSObjectIdentifiers.PKCS7DATA,contentEncryptionAlgorithmIdentifier,new DEROctetString(conts));

		} catch (SecurityException e) {
			throw new PKCS7Exception("Create RecipientInfos error!", e);

		}
		return ret;

	}

	/**
	 * 签名者信息
	 *
	 * <pre>
	 *  SignerInfo ::= SEQUENCE {
	 *      version Version,
	 *      issuerAndSerialNumber IssuerAndSerialNumber,
	 *      digestAlgorithm DigestAlgorithmIdentifier,
	 *      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
	 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
	 *      encryptedDigest EncryptedDigest,
	 *      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
	 *  }
	 *
	 *  EncryptedDigest ::= OCTET STRING
	 *
	 *  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	 *
	 *  DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
	 * </pre>
	 *
	 */
	private SignerInfo getSignerInfo(EncryptedContentInfo encryptedContentInfo,String signerCert,String keyno,byte[] indata)throws PKCS7Exception {
		SignerInfo ret = null;
		try {
			// 版本号，默认为0
			ASN1Integer version = new ASN1Integer(1);
			// 获取签名者证书的颁发者和序列号
			X509CertificateStructure certobj = DERToObj.getX509CertStructureFromDer(Base64.decode(signerCert));
			org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber issuerAndSerialNumber = new org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber(certobj.getIssuer(), certobj.getSerialNumber().getPositiveValue());
			// 信息摘要算法标识 --对特定内容和待鉴定属性进行摘要计算
			AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.SM3,null);
			// ----------------------------
			// 摘要加密算法标识 --用签名者私钥加密信息摘要和相关信息
			AlgorithmIdentifier digestEncryptionAlgorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.SM3WithSM2SIGN);

			SM2 sm2 = new SM2();
			byte[] signData=sm2.internalSign("SM3/ECC", "7", keyno,0, indata);
			DEROctetString encryptedDigest = new DEROctetString(signData);
			ret = new SignerInfo(version,issuerAndSerialNumber, digestAlgorithmIdentifier,null,digestEncryptionAlgorithmIdentifier, encryptedDigest, null);
		} catch (SecurityException e) {
			throw new PKCS7Exception("Create SignerInfo error!", e);
		} catch (CCITSecurityException e) {
			e.printStackTrace();
		}
		return ret;
	}



}
