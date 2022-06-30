package com.ccit.digitalenvelope.asn1structure;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * <p>
 * Title:
 * </p>
 *
 * <p>
 * Description:
 * </p>
 *
 * <p>
 * Copyright: Copyright (c) 2003
 * </p>
 *
 * <p>
 * Company: ccit
 * </p>
 *
 * @author ice
 * @version 1.0
 */
public class CERT_INFO {
	public X509Certificate x509cert;

	private String issuerDN;

	private String subjectDN;

	private String serialNumber;

	private String notBefore;

	private String notAfter;

	private byte[] publicKey;

	private int publicKeyLen;

	private int version;

	private Date notBeforeDate;

	private Date notAfterDate;

	private String sigAlgOID;

	public CERT_INFO(byte[] cert)  {
		try {

			ByteArrayInputStream bIn1 = new ByteArrayInputStream(cert);
			ASN1InputStream ais1 = new ASN1InputStream(bIn1);
			ASN1Primitive dobj1 = ais1.readObject();
			ASN1Sequence ass1 = (ASN1Sequence) dobj1;
			ais1.close();
			bIn1.close();
			bIn1 = null;
			X509CertificateStructure x509cert1 = new X509CertificateStructure(
					ass1);

			ByteArrayInputStream bis = new ByteArrayInputStream(cert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509",
					new BouncyCastleProvider());
			x509cert = (X509Certificate) cf.generateCertificate(bis);
			byte[] pubkey = null;
			if (Constants.SM2_SIG_OID.equals(x509cert.getSigAlgOID())) {
				ByteArrayInputStream bIn2 = new ByteArrayInputStream(cert);
				ASN1InputStream ais2 = new ASN1InputStream(bIn2);
				ASN1Primitive dobj2 = ais2.readObject();
				ASN1Sequence ass2 = (ASN1Sequence) dobj2;
				X509CertificateStructure x509certsm2 = new X509CertificateStructure(
						ass2);
				SubjectPublicKeyInfo spkspk = x509certsm2
						.getSubjectPublicKeyInfo();
				pubkey = spkspk.getEncoded();
				ais2.close();
				bIn2.close();
			} else {
//				pubkey = x509cert.getPublicKey().getEncoded();
				pubkey = x509cert1.getSubjectPublicKeyInfo()
						.getPublicKeyData().getBytes();
			}
			String certSN = x509cert.getSerialNumber().toString(16);
			if (!(certSN.length() % 2 == 0)) {
				certSN = "0" + certSN;
			}
			certSN = certSN.toLowerCase();
			setSerialNumber(certSN);
			setIssuerDN(x509cert.getIssuerDN().toString());
			setSubjectDN(x509cert.getSubjectDN().toString());
			setNotBefore(StringToDate(x509cert.getNotBefore()));
			setNotAfter(StringToDate(x509cert.getNotAfter()));
			setNotBeforeDate(x509cert.getNotBefore());
			setNotAfterDate(x509cert.getNotAfter());
			setPublicKey(pubkey);
			setPublicKeyLen(pubkey.length);
			setVersion(x509cert.getVersion());
			setSigAlgOID(x509cert.getSigAlgOID());
		} catch (Exception e) {
			e.printStackTrace();
		}

	}


	/**
	 * 二行制转换成十六进制数的字符串
	 *
	 * @param b
	 * @return
	 */
	public static String byteToHex(byte[] b) {

		String hs = "";
		String stmp = "";
		for (int n = 0; n < b.length; n++) {
			stmp = (Integer.toHexString(b[n] & 0XFF));
			if (stmp.length() == 1) {
				hs = hs + "0" + stmp;
			} else {
				hs = hs + stmp;
			}

		}
		return hs.toUpperCase();
	}

	public X509Certificate getX509(){
		return x509cert;
	}

	public String getSigAlgOID() {
		return sigAlgOID;
	}

	public void setSigAlgOID(String sigAlgOID) {
		this.sigAlgOID = sigAlgOID;
	}

	public void setIssuerDN(String issuerDN) {

		this.issuerDN = issuerDN;
	}

	public void setSubjectDN(String subjectDN) {
		this.subjectDN = subjectDN;
	}

	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	public void setNotBefore(String notBefore) {
		this.notBefore = notBefore;
	}

	public void setNotAfter(String notAfter) {
		this.notAfter = notAfter;
	}

	public void setPublicKey(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public void setPublicKeyLen(int publicKeyLen) {
		this.publicKeyLen = publicKeyLen;
	}

	public void setVersion(int version) {
		this.version = version;
	}

	public String getIssuerDN() {
		return issuerDN;
	}

	public String getSubjectDN() {
		return subjectDN;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public String getNotBefore() {
		return notBefore;
	}

	public String getNotAfter() {
		return notAfter;
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	public int getPublicKeyLen() {
		return publicKeyLen;
	}

	public int getVersion() {
		return version;
	}

	private static String StringToDate(Date param) {
		String strTime = "";
		try {

			GregorianCalendar calendar = new GregorianCalendar();
			calendar.setTime(param);

			int year = calendar.get(java.util.Calendar.YEAR);
			int month = calendar.get(java.util.Calendar.MONTH) + 1;
			int day = calendar.get(java.util.Calendar.DAY_OF_MONTH);
			int hour = calendar.get(java.util.Calendar.HOUR_OF_DAY);
			int minute = calendar.get(java.util.Calendar.MINUTE);
			int second = calendar.get(java.util.Calendar.SECOND);
			strTime = year
					+ (month >= 10 ? ("." + month) : (".0" + month))
					+ (day >= 10 ? ("." + day) : (".0" + day))
					+
					(hour >= 10 ? (" " + hour) : (" 0" + hour))
					+ (minute >= 10 ? (":" + minute) : (":0" + minute))
					+ (second >= 10 ? (":" + second) : (":0" + second));
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
		return strTime;
	}

	public Date getNotAfterDate() {
		return notAfterDate;
	}

	public void setNotAfterDate(Date notAfterDate) {
		this.notAfterDate = notAfterDate;
	}

	public Date getNotBeforeDate() {
		return notBeforeDate;
	}

	public void setNotBeforeDate(Date notBeforeDate) {
		this.notBeforeDate = notBeforeDate;
	}


}
