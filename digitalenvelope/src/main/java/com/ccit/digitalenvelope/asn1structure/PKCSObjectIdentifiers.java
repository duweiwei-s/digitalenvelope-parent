package com.ccit.digitalenvelope.asn1structure;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class PKCSObjectIdentifiers {

	public static final ASN1ObjectIdentifier PKCS7DATA = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.1");
	public static final ASN1ObjectIdentifier SM4_ECB = new ASN1ObjectIdentifier("1.2.156.10197.1.104");
	public static final ASN1ObjectIdentifier SM3 = new ASN1ObjectIdentifier("1.2.156.10197.1.401");
	public static final ASN1ObjectIdentifier SM3WithSM2Encryption = new ASN1ObjectIdentifier("1.2.156.10197.1.501");
	public static final ASN1ObjectIdentifier SM3WithSM2SIGN = new ASN1ObjectIdentifier("1.2.156.10197.1.301");
	public static final ASN1ObjectIdentifier SIGNEDANDENVELOPEDDATA = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.4");

}
