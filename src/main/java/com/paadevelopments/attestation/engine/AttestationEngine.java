package com.paadevelopments.attestation.engine;

import org.bouncycastle.asn1.ASN1OctetString;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AttestationEngine {

    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final long MAX_NONCE_AGE_MS = 2 * 60 * 1000; // 2 minutes

    // State Tracking Engines (Thread-Safe concurrent structures)
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

    public static AttestationResult parseAndroidAttestation(String base64Cert) {
        AttestationResult result = new AttestationResult();
        try {
            String cleanCert = base64Cert.trim().replaceAll("\\s", "");
            byte[] certBuffer = Base64.getDecoder().decode(cleanCert);

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBuffer));

            byte[] extValue = x509.getExtensionValue(ATTESTATION_OID);
            if (extValue == null) {
                System.out.println("Attestation extension OID not found inside components.");
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

                // 1. Extract attestationVersion
                if ((extValueBytes[cursor] & 0xFF) == 0x02) {
                    cursor += 2 + extValueBytes[cursor + 1];
                }
                // 2. Extract attestationSecurityLevel
                if ((extValueBytes[cursor] & 0xFF) == 0x0A || (extValueBytes[cursor] & 0xFF) == 0x02) {
                    int val = extValueBytes[cursor + 2];
                    result.attestationSecurityLevel = (val == 1) ? "TRUSTED_ENVIRONMENT" : (val == 2) ? "STRONGBOX" : "SOFTWARE";
                    cursor += 2 + extValueBytes[cursor + 1];
                }
                // 3. Extract keymasterVersion
                if ((extValueBytes[cursor] & 0xFF) == 0x02) {
                    cursor += 2 + extValueBytes[cursor + 1];
                }
                // 4. Extract keymasterSecurityLevel
                if ((extValueBytes[cursor] & 0xFF) == 0x0A || (extValueBytes[cursor] & 0xFF) == 0x02) {
                    int val = extValueBytes[cursor + 2];
                    result.keymasterSecurityLevel = (val == 1) ? "TRUSTED_ENVIRONMENT" : (val == 2) ? "STRONGBOX" : "SOFTWARE";
                }

                // =================================================================
                // MULTI-FLAVOR SIGNATURE SCAN FOR ROOT OF TRUST (TAG 704)
                // =================================================================
                int rotCursor = -1;
                int rotLen = 0;

                for (int i = 0; i < extValueBytes.length - 4; i++) {
                    // Flavor A: Standard ASN.1 Long-Form Identifier (0xBF 0x85 0x40)
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
                    // Flavor B: Short-Form Sequence Header (0xA4)
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

                        // Tag 0x01 = deviceLocked (Boolean)
                        if (tag == 0x01) {
                            result.isBootloaderLocked = extValueBytes[rotCursor + 2] != 0x00;
                        }

                        // Tag 0x0A = verifiedBootState (Enumerated)
                        if (tag == 0x0A) {
                            int bootStateVal = extValueBytes[rotCursor + 2];
                            System.out.println("--> Java Engine found Verified Boot State byte value: " + bootStateVal);
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
                } else {
                    System.out.println("CRITICAL: Root of Trust sequence structure missing in hardware payload.");
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

        if ("VERIFIED".equals(verifiedBootState)) score += 40;
        if (isBootloaderLocked) score += 25;
        if ("TRUSTED_ENVIRONMENT".equals(keymasterLevel) || "STRONGBOX".equals(keymasterLevel)) score += 20;
        if (!isRooted) score += 10;
        if (!isHookDetected) score += 5;

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