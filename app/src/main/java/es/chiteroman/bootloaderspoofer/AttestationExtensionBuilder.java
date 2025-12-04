package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;

import java.security.SecureRandom;

final class AttestationExtensionBuilder {
    private static final ASN1ObjectIdentifier ATTESTATION_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private AttestationExtensionBuilder() {
    }

    static Extension build(byte[] challenge, KeyboxData keybox) throws IOException {
        byte[] safeChallenge = challenge != null ? challenge : new byte[0];
        ASN1Sequence rootOfTrustSeq = buildRootOfTrust();

        ASN1Sequence softwareEnforced = new DERSequence();
        ASN1Sequence teeEnforced = new DERSequence(new ASN1Encodable[]{new DERTaggedObject(true, 704, rootOfTrustSeq)});

        ASN1Sequence keyDescription = new DERSequence(new ASN1Encodable[]{
                new ASN1Integer(4),
                new ASN1Enumerated(1),
                new ASN1Integer(4),
                new ASN1Enumerated(1),
                new DEROctetString(safeChallenge),
                new DEROctetString(new byte[0]),
                softwareEnforced,
                teeEnforced
        });

        return new Extension(ATTESTATION_OID, false, new DEROctetString(keyDescription));
    }

    private static ASN1Sequence buildRootOfTrust() {
        SecureRandom random = new SecureRandom();
        byte[] verifiedBootKey = new byte[32];
        byte[] verifiedBootHash = new byte[32];
        random.nextBytes(verifiedBootKey);
        random.nextBytes(verifiedBootHash);

        ASN1Encodable[] rootEncodables = new ASN1Encodable[]{
                new DEROctetString(verifiedBootKey),
                ASN1Boolean.TRUE,
                new ASN1Enumerated(0),
                new DEROctetString(verifiedBootHash)
        };
        return new DERSequence(rootEncodables);
    }
}
