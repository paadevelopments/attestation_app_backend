package com.paadevelopments.attestation.servlet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.paadevelopments.attestation.engine.AttestationEngine;
import com.paadevelopments.attestation.engine.AttestationEngine.AttestationResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.*;

@WebServlet(urlPatterns = {"/nonce", "/attest"})
public class AttestationServlet extends HttpServlet {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

    private static volatile boolean identityLoaded = false;
    private static final Object identityLock = new Object();
    private static final Map<String, String> APP_IDENTITY_MAP = new HashMap<>();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if ("/nonce".equals(req.getServletPath())) {
            handleNonceGeneration(resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if ("/attest".equals(req.getServletPath())) {
            handleAttestationSubmission(req, resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    private void ensureIdentityRegistryLoaded() {
        if (identityLoaded) return;
        synchronized (identityLock) {
            if (identityLoaded) return;
            try (InputStream is = getClass().getClassLoader().getResourceAsStream("attestation/app_identities.json")) {
                if (is == null) {
                    throw new RuntimeException("Missing attestation/app_identities.json");
                }
                JsonNode root = mapper.readTree(is);
                JsonNode apps = root.get("apps");
                if (apps != null && apps.isArray()) {
                    for (JsonNode app : apps) {
                        String pkg = app.get("packageName").asText().trim();
                        String cert = app.get("certFingerprintSha256").asText().trim();
                        APP_IDENTITY_MAP.put(pkg, cert);
                    }
                }
                identityLoaded = true;
                System.out.println("Loaded app identity entries: " + APP_IDENTITY_MAP.size());
            } catch (Exception e) {
                throw new RuntimeException("Failed to load app identity registry", e);
            }
        }
    }

    private void handleNonceGeneration(HttpServletResponse resp) throws IOException {
        byte[] nonceBytes = new byte[32];
        secureRandom.nextBytes(nonceBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : nonceBytes) {
            sb.append(String.format("%02x", b));
        }
        String nonce = sb.toString();
        AttestationEngine.nonceStore.put(nonce, System.currentTimeMillis());
        resp.setContentType("application/json");
        ObjectNode responseJson = mapper.createObjectNode();
        responseJson.put("nonce", nonce);
        responseJson.put("expiresIn", 120000);
        resp.getWriter().print(mapper.writeValueAsString(responseJson));
    }

    private boolean verifyAppIdentity(JsonNode rootNode) {
        String packageName = rootNode.has("packageName")
                ? rootNode.get("packageName").asText().trim()
                : "";
        String clientSignature = rootNode.has("signature")
                ? rootNode.get("signature").asText().trim()
                : "";
        if (packageName.isEmpty() || clientSignature.isEmpty()) {
            return false;
        }
        if (!APP_IDENTITY_MAP.containsKey(packageName)) {
            return false;
        }
        String expectedFingerprint = APP_IDENTITY_MAP.get(packageName);
        return expectedFingerprint.equalsIgnoreCase(clientSignature);
    }

    private void handleAttestationSubmission(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        PrintWriter out = resp.getWriter();
        try {
            JsonNode rootNode = mapper.readTree(req.getReader());
            ensureIdentityRegistryLoaded();
            String nonce = rootNode.has("nonce") ? rootNode.get("nonce").asText() : "";
            String nonceCheck = AttestationEngine.verifyNonce(nonce);
            if (!"VALID".equals(nonceCheck)) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                out.print("{\"success\":false,\"decision\":\"DENY\",\"reason\":\"" + nonceCheck + "\"}");
                return;
            }
            JsonNode chainNode = rootNode.get("certificateChain");
            if (chainNode == null || !chainNode.isArray() || chainNode.isEmpty()) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print("{\"success\":false,\"decision\":\"DENY\",\"reason\":\"INVALID_CERT_CHAIN\"}");
                return;
            }
            List<String> certificateChain = new ArrayList<>();
            for (JsonNode node : chainNode) {
                certificateChain.add(node.asText());
            }
            if (!AttestationEngine.verifyCertificateChain(certificateChain)) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                out.print("{\"success\":false,\"decision\":\"DENY\",\"reason\":\"CERTIFICATE_CHAIN_UNTRUSTED\"}");
                return;
            }
            boolean isRooted = rootNode.has("isRooted") && rootNode.get("isRooted").asBoolean();
            boolean isHookDetected = rootNode.has("isHookDetected") && rootNode.get("isHookDetected").asBoolean();
            String base64LeafCert = certificateChain.get(0);
            AttestationResult parsedAttestation = AttestationEngine.parseAndroidAttestation(base64LeafCert, nonce);
            if (parsedAttestation == null) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print("{\"success\":false,\"decision\":\"DENY\",\"reason\":\"CRYPTO_PARSING_FAILED\"}");
                return;
            }
            boolean appIdentityValid = verifyAppIdentity(rootNode);
            boolean policyAllow = parsedAttestation.isHardwareBacked &&
                            "VERIFIED".equals(parsedAttestation.verifiedBootState) &&
                            parsedAttestation.isBootloaderLocked &&
                            !isRooted &&
                            !isHookDetected &&
                            appIdentityValid;
            if (!policyAllow) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                out.print("{\"success\":false,\"decision\":\"DENY\",\"reason\":\"POLICY_REJECTED\"}");
                return;
            }
            ObjectNode responseJson = mapper.createObjectNode();
            responseJson.put("success", true);
            responseJson.put("decision", "ALLOW");
            responseJson.put("reason", "OK");
            responseJson.put("verifiedBootState", parsedAttestation.verifiedBootState);
            responseJson.put("bootloaderLocked", parsedAttestation.isBootloaderLocked);
            responseJson.put("attestationSecurityLevel", parsedAttestation.attestationSecurityLevel);
            responseJson.put("keymasterSecurityLevel", parsedAttestation.keymasterSecurityLevel);
            out.print(mapper.writeValueAsString(responseJson));
        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.print("{\"success\":false,\"decision\":\"DENY\",\"reason\":\"SERVER_ERROR\",\"message\":\"" + e.getMessage() + "\"}");
        }
    }
}