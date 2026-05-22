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
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.UUID;

@WebServlet(urlPatterns = {"/nonce", "/attest"})
public class AttestationServlet extends HttpServlet {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

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
        responseJson.put("expiresIn", 120000); // 2 minutes

        resp.getWriter().print(mapper.writeValueAsString(responseJson));
    }

    private void handleAttestationSubmission(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        PrintWriter out = resp.getWriter();

        try {
            JsonNode rootNode = mapper.readTree(req.getReader());
            String nonce = rootNode.has("nonce") ? rootNode.get("nonce").asText() : "";
            
            // 1. Run Nonce / Replay Verification Check
            String nonceCheck = AttestationEngine.verifyNonce(nonce);
            if (!"VALID".equals(nonceCheck)) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                out.print("{\"success\":false,\"reason\":\"" + nonceCheck + "\"}");
                return;
            }

            // 2. Format and Verify Certificate Payload Arrays
            JsonNode chainNode = rootNode.get("certificateChain");
            if (chainNode == null || !chainNode.isArray() || chainNode.size() == 0) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print("{\"success\":false,\"reason\":\"INVALID_CERT_CHAIN\"}");
                return;
            }

            boolean isRooted = rootNode.has("isRooted") && rootNode.get("isRooted").asBoolean();
            boolean isHookDetected = rootNode.has("isHookDetected") && rootNode.get("isHookDetected").asBoolean();
            String base64LeafCert = chainNode.get(0).asText();

            // 3. Cryptographic Hardware State Interception
            AttestationResult parsedAttestation = AttestationEngine.parseAndroidAttestation(base64LeafCert);
            System.out.println("Parsed Hardware Attestation Output: " + mapper.writeValueAsString(parsedAttestation));

            if (parsedAttestation == null) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print("{\"success\":false,\"reason\":\"CRYPTO_PARSING_FAILED\"}");
                return;
            }

            // 4. Policy Execution Matrix Calculation
            int score = AttestationEngine.computeTrustScore(
                    parsedAttestation.verifiedBootState,
                    parsedAttestation.isBootloaderLocked,
                    parsedAttestation.keymasterSecurityLevel,
                    isRooted,
                    isHookDetected
            );

            String decision = "REJECT";
            boolean success = false;

            if (score >= 75) {
                decision = "APPROVE";
                success = true;
            } else if (score >= 60) {
                decision = "REVIEW";
            }

            String sessionId = null;
            if (success) {
                sessionId = UUID.randomUUID().toString();
                AttestationEngine.sessionStore.put(sessionId, score);
            }

            // 5. Build Comprehensive Output Object payload
            ObjectNode responseJson = mapper.createObjectNode();
            responseJson.put("success", success);
            responseJson.put("decision", decision);
            responseJson.put("trustScore", score);
            responseJson.put("sessionId", sessionId);

            ObjectNode policyJson = mapper.createObjectNode();
            ObjectNode weightsJson = mapper.createObjectNode();
            weightsJson.put("verifiedBoot", 40);
            weightsJson.put("rootOfTrust", 25);
            weightsJson.put("keymaster", 20);
            weightsJson.put("rootDetected", 10);
            weightsJson.put("hookDetected", 5);
            
            ObjectNode thresholdsJson = mapper.createObjectNode();
            thresholdsJson.put("approve", 75);
            thresholdsJson.put("reject", 60);

            policyJson.set("weights", weightsJson);
            policyJson.set("thresholds", thresholdsJson);
            responseJson.set("policy", policyJson);

            out.print(mapper.writeValueAsString(responseJson));

        } catch (Exception e) {
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.print("{\"success\":false,\"reason\":\"SERVER_ERROR\",\"message\":\"" + e.getMessage() + "\"}");
        }
    }
}