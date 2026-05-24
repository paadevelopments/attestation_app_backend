package com.paadevelopments.attestation.engine;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AttestationEngine {
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final long MAX_NONCE_AGE_MS = 2 * 60 * 1000;
    public static final Map<String, Long> nonceStore = new ConcurrentHashMap<>();
    public static final Set<String> usedNonceStore = ConcurrentHashMap.newKeySet();

    public static class AttestationResult {
        public boolean isValidChainElement = false;
        public String attestationSecurityLevel = "UNKNOWN";
        public String keymasterSecurityLevel = "UNKNOWN";
        public boolean isBootloaderLocked = false;
        public String verifiedBootState = "UNKNOWN";
        public boolean isHardwareBacked = false;
    }

    public static boolean verifyCertificateChain(List<String> base64Chain) {
        try {
            if (base64Chain == null || base64Chain.isEmpty()) {
                System.err.println("REJECTED: Empty certificate chain.");
                return false;
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();
            for (String base64 : base64Chain) {
                String clean = base64.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s+", "");
                byte[] der = Base64.getDecoder().decode(clean);
                X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
                cert.checkValidity();
                certs.add(cert);
            }
            if (certs.size() > 1 && certs.get(0).getExtensionValue(ATTESTATION_OID) == null) {
                Collections.reverse(certs);
            }
            CertPath certPath = factory.generateCertPath(certs);
            PKIXParameters params = new PKIXParameters(TrustedRootRegistry.getTrustAnchors());
            params.setRevocationEnabled(false);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);
            TrustAnchor anchor = result.getTrustAnchor();
            X509Certificate trustedRoot = anchor.getTrustedCert();
            System.out.println("SUCCESS: Chain validated against Google root: " + trustedRoot.getSubjectX500Principal());
            X509Certificate leaf = certs.get(0);
            byte[] attestationExtension = leaf.getExtensionValue(ATTESTATION_OID);
            if (attestationExtension == null) {
                System.err.println("REJECTED: Missing Android attestation extension.");
                return false;
            }
            if (leaf.getPublicKey() == null) {
                System.err.println("REJECTED: Invalid leaf public key.");
                return false;
            }
            System.out.println("SUCCESS: Android attestation extension verified.");
            return true;
        } catch (CertPathValidatorException e) {
            System.err.println("REJECTED: PKIX validation failed at index " + e.getIndex() + " reason=" + e.getReason());
            return false;
        } catch (Exception e) {
            System.err.println("CRITICAL: Attestation verification failure: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static AttestationResult parseAndroidAttestation(String base64Cert, String expectedNonce) {
        AttestationResult result = new AttestationResult();
        try {
            String cleanCert = base64Cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s+", "");
            byte[] certBuffer = Base64.getDecoder().decode(cleanCert);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBuffer));
            byte[] extValue = x509.getExtensionValue(ATTESTATION_OID);
            if (extValue == null) {
                System.err.println("Attestation extension OID missing.");
                return null;
            }
            ASN1OctetString octetString = ASN1OctetString.getInstance(extValue);
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(octetString.getOctets());
            ASN1Sequence keyDescription = ASN1Sequence.getInstance(primitive);
            ASN1OctetString challenge = ASN1OctetString.getInstance(keyDescription.getObjectAt(4));
            String challengeString = new String(challenge.getOctets(), StandardCharsets.UTF_8);
            if (!expectedNonce.equals(challengeString)) {
                System.err.println("REJECTED: Attestation nonce mismatch.");
                return null;
            }
            System.out.println("SUCCESS: Attestation challenge verified.");
            result.isValidChainElement = true;
            ASN1Enumerated attestationSecurityLevel = ASN1Enumerated.getInstance(keyDescription.getObjectAt(1));
            result.attestationSecurityLevel = securityLevelToString(attestationSecurityLevel.getValue().intValue());
            ASN1Enumerated keymasterSecurityLevel = ASN1Enumerated.getInstance(keyDescription.getObjectAt(3));
            result.keymasterSecurityLevel = securityLevelToString(keymasterSecurityLevel.getValue().intValue());
            result.isHardwareBacked = !"SOFTWARE".equals(result.attestationSecurityLevel) && !"SOFTWARE".equals(result.keymasterSecurityLevel);
            ASN1Sequence rootOfTrust = extractRootOfTrust(keyDescription);
            if (rootOfTrust != null) {
                for (int i = 0; i < rootOfTrust.size(); i++) {
                    ASN1Encodable enc = rootOfTrust.getObjectAt(i);
                    if (enc instanceof ASN1Boolean) {
                        result.isBootloaderLocked = ((ASN1Boolean) enc).isTrue();
                    }
                    if (enc instanceof ASN1Enumerated) {
                        int state = ((ASN1Enumerated) enc).getValue().intValue();
                        switch (state) {
                            case 0: result.verifiedBootState = "VERIFIED"; break;
                            case 1: result.verifiedBootState = "SELF_SIGNED"; break;
                            case 2: result.verifiedBootState = "UNVERIFIED"; break;
                            case 3: result.verifiedBootState = "FAILED"; break;
                            default: result.verifiedBootState = "UNKNOWN";
                        }
                    }
                }
            }
            return result;
        } catch (Exception e) {
            System.err.println("Cryptographic hardware block verification failure: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static ASN1Sequence extractRootOfTrust(ASN1Sequence keyDescription) {
        try {
            ASN1Encodable teeObj = keyDescription.getObjectAt(7);
            ASN1Sequence teeEnforced;
            if (teeObj instanceof ASN1Sequence) {
                teeEnforced = (ASN1Sequence) teeObj;
            } else if (teeObj instanceof ASN1OctetString) {
                ASN1OctetString oct = (ASN1OctetString) teeObj;
                ASN1Primitive primitive = ASN1Primitive.fromByteArray(oct.getOctets());
                teeEnforced = ASN1Sequence.getInstance(primitive);
            } else {
                return null;
            }
            for (ASN1Encodable enc : teeEnforced) {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(enc);
                if (tagged.getTagNo() == 704) {
                    ASN1Encodable obj = tagged.getBaseObject();
                    if (obj instanceof ASN1Sequence) return (ASN1Sequence) obj;
                    if (obj instanceof ASN1OctetString) {
                        ASN1OctetString oct = (ASN1OctetString) obj;
                        ASN1Primitive primitive = ASN1Primitive.fromByteArray(oct.getOctets());
                        return ASN1Sequence.getInstance(primitive);
                    }
                    ASN1Primitive primitive = obj.toASN1Primitive();
                    if (primitive instanceof ASN1Sequence) return (ASN1Sequence) primitive;
                    if (primitive instanceof ASN1OctetString) {
                        ASN1OctetString oct = (ASN1OctetString) primitive;
                        return ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(oct.getOctets()));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("RootOfTrust extraction failed: " + e.getMessage());
        }
        return null;
    }

    private static String securityLevelToString(int level) {
        return switch (level) {
            case 0 -> "SOFTWARE";
            case 1 -> "TRUSTED_ENVIRONMENT";
            case 2 -> "STRONGBOX";
            default -> "UNKNOWN";
        };
    }

    public static String verifyNonce(String nonce) {
        if (!nonceStore.containsKey(nonce)) return "UNKNOWN_NONCE";
        if (usedNonceStore.contains(nonce)) return "REPLAY_DETECTED";
        long createdAt = nonceStore.get(nonce);
        long now = System.currentTimeMillis();
        if (now - createdAt > MAX_NONCE_AGE_MS) return "NONCE_EXPIRED";
        usedNonceStore.add(nonce);
        nonceStore.remove(nonce);
        return "VALID";
    }
}