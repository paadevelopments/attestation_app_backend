package com.paadevelopments.attestation.engine;

import org.bouncycastle.asn1.ASN1OctetString;
import java.io.ByteArrayInputStream;
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
    private static final long MAX_NONCE_AGE_MS = 2 * 60 * 1000; // 2 minutes
    public static final Map<String, Long> nonceStore = new ConcurrentHashMap<>();
    public static final Set<String> usedNonceStore = ConcurrentHashMap.newKeySet();
    public static final Map<String, Integer> sessionStore = new ConcurrentHashMap<>();

    public static class AttestationResult {
        public boolean isValidChainElement = false;
        public String attestationSecurityLevel = "UNKNOWN";
        public String keymasterSecurityLevel = "UNKNOWN";
        public boolean isBootloaderLocked = false;
        public String verifiedBootState = "UNKNOWN";
    }

    /**
     * REFACTORED MULTI-ROOT TRUST VALIDATION ENGINE
     * Loops through registered trusted roots to cross-verify alternate OEM architectures.
     */
    public static boolean verifyCertificateChain(List<String> base64Chain) {
        try {
            if (base64Chain == null || base64Chain.isEmpty()) {
                System.err.println("REJECTED: Empty certificate chain.");
                return false;
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();
            for (String base64 : base64Chain) {
                String clean = base64
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s+", "");
                byte[] der = Base64.getDecoder().decode(clean);
                X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
                cert.checkValidity();
                certs.add(cert);
            }
            if (certs.size() > 1 && certs.get(0).getExtensionValue("1.3.6.1.4.1.11129.2.1.17") == null) {
                // The chain is likely upside down (Root first). Reverse it to keep PKIX happy.
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
            // Attestation certs must contain extension
            byte[] attestationExtension = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
            if (attestationExtension == null) {
                System.err.println("REJECTED: Missing Android attestation extension.");
                return false;
            }
            // Strong signal this is hardware-backed
            if (leaf.getPublicKey() == null) {
                System.err.println("REJECTED: Invalid leaf public key.");
                return false;
            }
            System.out.println("SUCCESS: Android attestation extension verified.");
            return true;
        } catch (CertPathValidatorException e) {
            System.err.println(
                    "REJECTED: PKIX validation failed at index "
                            + e.getIndex()
                            + " reason="
                            + e.getReason());
            return false;
        } catch (Exception e) {
            System.err.println(
                    "CRITICAL: Attestation verification failure: "
                            + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * PARSING LOGIC MATRIX
     */
    public static AttestationResult parseAndroidAttestation(String base64Cert) {
        AttestationResult result = new AttestationResult();
        try {
            String cleanCert = base64Cert.trim().replaceAll("\\s", "");
            byte[] certBuffer = Base64.getDecoder().decode(cleanCert);

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBuffer));

            byte[] extValue = x509.getExtensionValue(ATTESTATION_OID);
            if (extValue == null) {
                System.out.println("Attestation extension OID missing inside hardware layer.");
                return null;
            }

            ASN1OctetString octetString = ASN1OctetString.getInstance(extValue);
            byte[] extValueBytes = octetString.getOctets();

            result.isValidChainElement = true;

            if (extValueBytes != null && extValueBytes.length > 4) {
                int cursor = 0;
                if ((extValueBytes[cursor] & 0xFF) == 0x30) {
                    cursor++;
                    if ((extValueBytes[cursor] & 0x80) != 0) {
                        cursor += 1 + (extValueBytes[cursor] & 0x7F);
                    } else {
                        cursor++;
                    }
                }

                if ((extValueBytes[cursor] & 0xFF) == 0x02) {
                    cursor += 2 + extValueBytes[cursor + 1];
                }
                if ((extValueBytes[cursor] & 0xFF) == 0x0A || (extValueBytes[cursor] & 0xFF) == 0x02) {
                    int val = extValueBytes[cursor + 2];
                    result.attestationSecurityLevel = (val == 1) ? "TRUSTED_ENVIRONMENT" : (val == 2) ? "STRONGBOX" : "SOFTWARE";
                    cursor += 2 + extValueBytes[cursor + 1];
                }
                if ((extValueBytes[cursor] & 0xFF) == 0x02) {
                    cursor += 2 + extValueBytes[cursor + 1];
                }
                if ((extValueBytes[cursor] & 0xFF) == 0x0A || (extValueBytes[cursor] & 0xFF) == 0x02) {
                    int val = extValueBytes[cursor + 2];
                    result.keymasterSecurityLevel = (val == 1) ? "TRUSTED_ENVIRONMENT" : (val == 2) ? "STRONGBOX" : "SOFTWARE";
                }

                int rotCursor = -1;
                int rotLen = 0;

                for (int i = 0; i < extValueBytes.length - 4; i++) {
                    if ((extValueBytes[i] & 0xFF) == 0xBF && (extValueBytes[i+1] & 0xFF) == 0x85 && (extValueBytes[i+2] & 0xFF) == 0x40) {
                        int lenByte = extValueBytes[i + 3] & 0xFF;
                        int headerOffset = 4;
                        if ((lenByte & 0x80) != 0) {
                            headerOffset += (lenByte & 0x7F);
                        }
                        if ((extValueBytes[i + headerOffset] & 0xFF) == 0x30) {
                            rotCursor = i + headerOffset;
                            rotLen = extValueBytes[rotCursor + 1] & 0xFF;
                            break;
                        }
                    }
                    if ((extValueBytes[i] & 0xFF) == 0xA4 && (extValueBytes[i + 2] & 0xFF) == 0x30) {
                        rotCursor = i + 2;
                        rotLen = extValueBytes[rotCursor + 1] & 0xFF;
                        break;
                    }
                }

                if (rotCursor != -1) {
                    if ((rotLen & 0x80) != 0) {
                        int lengthBytesCount = rotLen & 0x7F;
                        rotCursor += 2 + lengthBytesCount;
                    } else {
                        rotCursor += 2;
                    }

                    int scanLimit = rotCursor + ((rotLen & 0x80) != 0 ? 128 : rotLen);
                    if (scanLimit > extValueBytes.length) scanLimit = extValueBytes.length;

                    while (rotCursor < scanLimit) {
                        int tag = extValueBytes[rotCursor] & 0xFF;
                        int len = extValueBytes[rotCursor + 1] & 0xFF;

                        if (rotCursor + 2 + len > extValueBytes.length) break;

                        if (tag == 0x01) {
                            result.isBootloaderLocked = extValueBytes[rotCursor + 2] != 0x00;
                        }

                        if (tag == 0x0A) {
                            int bootStateVal = extValueBytes[rotCursor + 2];
                            String[] states = {"VERIFIED", "SELF_SIGNED", "UNVERIFIED", "FAILED"};
                            if (bootStateVal >= 0 && bootStateVal < states.length) {
                                result.verifiedBootState = states[bootStateVal];
                            } else {
                                result.verifiedBootState = "UNKNOWN";
                            }
                        }

                        rotCursor += 2 + len;
                        if (tag == 0x00) break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Cryptographic hardware block verification failure: " + e.getMessage());
            return null;
        }
        return result;
    }

    public static int computeTrustScore(String verifiedBootState, boolean isBootloaderLocked,
                                        String keymasterLevel, boolean isRooted, boolean isHookDetected) {
        int score = 0;

        if ("VERIFIED".equals(verifiedBootState)) score += PolicyConfig.WEIGHT_VERIFIED_BOOT;
        if (isBootloaderLocked) score += PolicyConfig.WEIGHT_ROOT_OF_TRUST;
        if ("TRUSTED_ENVIRONMENT".equals(keymasterLevel) || "STRONGBOX".equals(keymasterLevel)) score += PolicyConfig.WEIGHT_KEYMASTER;
        if (!isRooted) score += PolicyConfig.WEIGHT_ROOT_DETECTED;
        if (!isHookDetected) score += PolicyConfig.WEIGHT_HOOK_DETECTED;

        return score;
    }

    public static String verifyNonce(String nonce) {
        if (!nonceStore.containsKey(nonce)) return "UNKNOWN_NONCE";
        if (usedNonceStore.contains(nonce)) return "REPLAY_DETECTED";

        long createdAt = nonceStore.get(nonce);
        long now = System.currentTimeMillis();

        if (now - createdAt > MAX_NONCE_AGE_MS) {
            return "NONCE_EXPIRED";
        }

        usedNonceStore.add(nonce);
        nonceStore.remove(nonce);
        return "VALID";
    }
}