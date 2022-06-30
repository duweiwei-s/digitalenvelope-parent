package com.ccit.digitalenvelope.asn1structure;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptContentInfo implements ASN1Encodable {
    private ASN1ObjectIdentifier contentType;
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private ASN1OctetString encryptedContent;

    public static EncryptContentInfo getInstance(ASN1TaggedObject obj,
                                                 boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EncryptContentInfo getInstance(Object obj) {
        if (obj instanceof EncryptContentInfo) {
            return (EncryptContentInfo) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new EncryptContentInfo((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }

    public EncryptContentInfo(ASN1ObjectIdentifier contentType,
                              AlgorithmIdentifier contentEncryptionAlgorithm,
                              ASN1OctetString encryptedContent) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }

    public EncryptContentInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        contentType = (ASN1ObjectIdentifier) e.nextElement();
        contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(e
                .nextElement());

        while (e.hasMoreElements()) {
            ASN1Object o = (ASN1Object) e.nextElement();
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        encryptedContent = ASN1OctetString.getInstance(tagged,
                                false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value "
                                + tagged.getTagNo());
                }
            } else {
                throw new IllegalArgumentException("unknown object in factory");
            }
        }
        //        if (seq.size() > 2)
        //        {
        //            encryptedContent = ASN1OctetString.getInstance(
        //                                (ASN1TaggedObject)seq.getObjectAt(2), false);
        //        }
    }

    public void setContentType(ASN1ObjectIdentifier contentType) {
        this.contentType = contentType;
    }

    public void setContentEncryptionAlgorithm(
            AlgorithmIdentifier contentEncryptionAlgorithm) {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }

    public void setEncryptedContent(ASN1OctetString encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    public ASN1ObjectIdentifier getContentType() {
        return contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent() {
        return encryptedContent;
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(contentType);
        v.add(contentEncryptionAlgorithm);

        if (encryptedContent != null) {
            v.add(new DERTaggedObject(false, 0, encryptedContent));
        }

        return new DERSequence(v);
    }
}
