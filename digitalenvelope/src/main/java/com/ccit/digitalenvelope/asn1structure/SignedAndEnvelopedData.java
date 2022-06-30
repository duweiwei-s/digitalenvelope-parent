package com.ccit.digitalenvelope.asn1structure;

import java.io.Serializable;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * SignedAndEnvelopedData ::= SEQUENCE {
 *          version                         Version,
 *          recipientInfos                  RecipientInfos,
 *          digestAlgorithms                DigestAlgorithmIdentifiers,
 *          encryptedContentInfo            EncryptedContentInfo,
 *          certificates             [0]    IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *          crls                     [1]    IMPLICIT CertificateRevocationLists OPTIONAL,
 *          signerInfos                     SignerInfos 
 * }
 *
 * </pre>
 */
public class SignedAndEnvelopedData implements ASN1Encodable,Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -2405921984073981258L;
    private ASN1Integer version;
    private ASN1Set recipientInfos;
    private ASN1Set digestAlgorithms;
    private EncryptedContentInfo encryptedContentInfo;
    private ASN1Set certificates;
    private ASN1Set crls;
    private ASN1Set signerInfos;

    public SignedAndEnvelopedData() {

    }

    public static SignedAndEnvelopedData getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SignedAndEnvelopedData getInstance(Object obj) {
        if (obj instanceof SignedAndEnvelopedData) {
            return (SignedAndEnvelopedData) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new SignedAndEnvelopedData((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }

    public SignedAndEnvelopedData(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();

        version = ASN1Integer.getInstance(e.nextElement());
        recipientInfos = ASN1Set.getInstance(e.nextElement());
        digestAlgorithms = ASN1Set.getInstance(e.nextElement());
        encryptedContentInfo = EncryptedContentInfo.getInstance(e.nextElement());

        while (e.hasMoreElements()) {
            ASN1Object o = (ASN1Object) e.nextElement();

            //
            // an interesting feature of SignedData is that there appear
            // to be varying implementations...
            // for the moment we ignore anything which doesn't fit.
            //
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;

                switch (tagged.getTagNo()) {
                    case 0:
                        certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
                        crls = ASN1Set.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value "
                                + tagged.getTagNo());
                }
            } else {
                signerInfos = (ASN1Set) o;
            }
        }
    }

    public SignedAndEnvelopedData(ASN1Integer version, ASN1Set recipientInfos,
                                  ASN1Set digestAlgorithms,
                                  EncryptedContentInfo encryptedContentInfo, ASN1Set certificates,
                                  ASN1Set crls, ASN1Set signerInfos) {
        this.version = version;
        this.recipientInfos = recipientInfos;
        this.digestAlgorithms = digestAlgorithms;
        this.encryptedContentInfo = encryptedContentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
    }


    public ASN1Integer getVersion() {
        return version;
    }

    public void setVersion(ASN1Integer version) {
        this.version = version;
    }

    public ASN1Set getRecipientInfos() {
        return recipientInfos;
    }

    public void setRecipientInfos(ASN1Set recipientInfos) {
        this.recipientInfos = recipientInfos;
    }

    public ASN1Set getDigestAlgorithms() {
        return digestAlgorithms;
    }

    public void setDigestAlgorithms(ASN1Set digestAlgorithms) {
        this.digestAlgorithms = digestAlgorithms;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }

    public void setEncryptedContentInfo(
            EncryptedContentInfo encryptedContentInfo) {
        this.encryptedContentInfo = encryptedContentInfo;
    }

    public ASN1Set getCertificates() {
        return certificates;
    }

    public void setCertificates(ASN1Set certificates) {
        this.certificates = certificates;
    }

    public ASN1Set getCrls() {
        return crls;
    }

    public void setCrls(ASN1Set crls) {
        this.crls = crls;
    }

    public ASN1Set getSignerInfos() {
        return signerInfos;
    }

    public void setSignerInfos(ASN1Set signerInfos) {
        this.signerInfos = signerInfos;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(recipientInfos);
        v.add(digestAlgorithms);
        v.add(encryptedContentInfo);
        if (certificates != null)
            v.add(new DERTaggedObject(false, 0, certificates));
        if (crls != null)
            v.add(new DERTaggedObject(false, 1, crls));
        v.add(signerInfos);

        return new DERSequence(v);
    }

}
