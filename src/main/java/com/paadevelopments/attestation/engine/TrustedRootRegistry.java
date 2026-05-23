package com.paadevelopments.attestation.engine;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

public final class TrustedRootRegistry {

    private static final Set<TrustAnchor> TRUST_ANCHORS = new HashSet<>();
    private static final Map<String, X509Certificate> ROOTS = new HashMap<>();

    static {
        try {
            loadPem("attestation/google_attestation_rsa.pem");
            loadPem("attestation/google_attestation_ecdsa.pem");
            System.out.println("Loaded trusted attestation roots: " + ROOTS.size());

        } catch (Exception e) {
            throw new RuntimeException("Failed loading attestation roots", e);
        }
    }

    private static void loadPem(String resourcePath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = TrustedRootRegistry.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalStateException("Missing resource: " + resourcePath);
            }
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            String fingerprint = sha256(cert.getEncoded());
            ROOTS.put(fingerprint, cert);
            TRUST_ANCHORS.add(new TrustAnchor(cert, null));
            System.out.println("Enrolled root: " + cert.getSubjectX500Principal());
        }
    }

    private static String sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static Set<TrustAnchor> getTrustAnchors() {
        return TRUST_ANCHORS;
    }
}