package com.ccit.digitalenvelope.asn1structure;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

import com.ccit.digitalenvelope.exception.CCITSecurityException;


public class DERToObj {

	public static X509CertificateStructure getX509CertStructureFromDer(byte[] cert) throws CCITSecurityException{
		if(cert==null){
			throw new CCITSecurityException("DER certificate can not be null!");
		}
		try {
			ASN1Sequence ass = getASN1Sequence(cert);
			X509CertificateStructure x509cert = new X509CertificateStructure(
					ass);
			return x509cert;
		} catch (CCITSecurityException e) {
			throw new CCITSecurityException("Parse certificate failed!", e);
		} catch (Exception e) {
			throw new CCITSecurityException("Parse certificate failed!", e);
		}


	}

	public static ASN1Sequence getASN1Sequence(byte[] data)
			throws CCITSecurityException {
		if(data==null){
			throw new CCITSecurityException("DER data can not be null!");
		}
		try {
			ByteArrayInputStream bIn = new ByteArrayInputStream(data);
			ASN1InputStream encais = new ASN1InputStream(bIn);
			ASN1Primitive encdobj = encais.readObject();
			ASN1Sequence encass = (ASN1Sequence) encdobj;
			return encass;
		} catch (IOException e) {
			e.printStackTrace();
			throw new CCITSecurityException(e.getMessage(), e);
		} catch (Exception e) {
			throw new CCITSecurityException(e.getMessage(), e);
		}
	}

}
