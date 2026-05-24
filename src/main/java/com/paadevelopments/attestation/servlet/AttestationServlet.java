package com.paadevelopments.attestation.servlet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.paadevelopments.attestation.engine.AttestationEngine;
import com.paadevelopments.attestation.engine.AttestationEngine.AttestationResult;
import com.paadevelopments.attestation.engine.PolicyConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@WebServlet(urlPatterns = {"/nonce", "/attest"})
public class AttestationServlet extends HttpServlet {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

    private static final ObjectNode STATIC_POLICY_JSON;

    static {
        ObjectMapper initMapper = new ObjectMapper();

        ObjectNode policyJson = initMapper.createObjectNode();
        ObjectNode weightsJson = initMapper.createObjectNode();
        ObjectNode thresholdsJson = initMapper.createObjectNode();

        weightsJson.put("verifiedBoot", PolicyConfig.WEIGHT_VERIFIED_BOOT);
        weightsJson.put("rootOfTrust", PolicyConfig.WEIGHT_ROOT_OF_TRUST);
        weightsJson.put("keymaster", PolicyConfig.WEIGHT_KEYMASTER);
        weightsJson.put("rootDetected", PolicyConfig.WEIGHT_ROOT_DETECTED);
        weightsJson.put("hookDetected", PolicyConfig.WEIGHT_HOOK_DETECTED);

        thresholdsJson.put("approve", PolicyConfig.THRESHOLD_APPROVE);
        thresholdsJson.put("reject", PolicyConfig.THRESHOLD_REJECT);

        policyJson.set("weights", weightsJson);
        policyJson.set("thresholds", thresholdsJson);

        STATIC_POLICY_JSON = policyJson.deepCopy();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        if ("/nonce".equals(req.getServletPath())) {
            handleNonceGeneration(resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        if ("/attest".equals(req.getServletPath())) {
            handleAttestationSubmission(req, resp);
        } else {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        }
    }

    private void handleNonceGeneration(HttpServletResponse resp)
            throws IOException {

        byte[] nonceBytes = new byte[32];
        secureRandom.nextBytes(nonceBytes);

        StringBuilder sb = new StringBuilder();

        for (byte b : nonceBytes) {
            sb.append(String.format("%02x", b));
        }

        String nonce = sb.toString();

        AttestationEngine.nonceStore.put(
                nonce,
                System.currentTimeMillis());

        resp.setContentType("application/json");

        ObjectNode responseJson = mapper.createObjectNode();
        responseJson.put("nonce", nonce);
        responseJson.put("expiresIn", 120000);

        resp.getWriter().print(
                mapper.writeValueAsString(responseJson));
    }

    private void handleAttestationSubmission(
            HttpServletRequest req,
            HttpServletResponse resp)
            throws IOException {

        resp.setContentType("application/json");

        PrintWriter out = resp.getWriter();

        try {

            JsonNode rootNode = mapper.readTree(req.getReader());

            String nonce =
                    rootNode.has("nonce")
                            ? rootNode.get("nonce").asText()
                            : "";

            String nonceCheck =
                    AttestationEngine.verifyNonce(nonce);

            if (!"VALID".equals(nonceCheck)) {

                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);

                out.print(
                        "{\"success\":false,\"reason\":\""
                                + nonceCheck
                                + "\"}");

                return;
            }

            JsonNode chainNode =
                    rootNode.get("certificateChain");

            if (chainNode == null
                    || !chainNode.isArray()
                    || chainNode.isEmpty()) {

                resp.setStatus(
                        HttpServletResponse.SC_BAD_REQUEST);

                out.print(
                        "{\"success\":false,\"reason\":\"INVALID_CERT_CHAIN\"}");

                return;
            }

            List<String> certificateChain =
                    new ArrayList<>();

            for (JsonNode node : chainNode) {
                certificateChain.add(node.asText());
            }

            if (!AttestationEngine.verifyCertificateChain(
                    certificateChain)) {

                resp.setStatus(
                        HttpServletResponse.SC_FORBIDDEN);

                out.print(
                        "{\"success\":false,\"reason\":\"CERTIFICATE_CHAIN_UNTRUSTED\"}");

                return;
            }

            boolean isRooted =
                    rootNode.has("isRooted")
                            && rootNode.get("isRooted").asBoolean();

            boolean isHookDetected =
                    rootNode.has("isHookDetected")
                            && rootNode.get("isHookDetected").asBoolean();

            String base64LeafCert =
                    certificateChain.get(0);

            AttestationResult parsedAttestation =
                    AttestationEngine.parseAndroidAttestation(
                            base64LeafCert,
                            nonce);

            System.out.println(
                    "Parsed Hardware Attestation Output: "
                            + mapper.writeValueAsString(
                            parsedAttestation));

            if (parsedAttestation == null) {

                resp.setStatus(
                        HttpServletResponse.SC_BAD_REQUEST);

                out.print(
                        "{\"success\":false,\"reason\":\"CRYPTO_PARSING_FAILED\"}");

                return;
            }

            if (!parsedAttestation.isHardwareBacked) {

                resp.setStatus(
                        HttpServletResponse.SC_FORBIDDEN);

                out.print(
                        "{\"success\":false,\"reason\":\"SOFTWARE_ATTESTATION_REJECTED\"}");

                return;
            }

            if (!"VERIFIED".equals(parsedAttestation.verifiedBootState)) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                out.print("{\"success\":false,\"reason\":\"BOOT_STATE_NOT_VERIFIED\"}");
                return;
            }

            if (!parsedAttestation.isBootloaderLocked) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                out.print("{\"success\":false,\"reason\":\"BOOTLOADER_UNLOCKED\"}");
                return;
            }

            int score = AttestationEngine.computeTrustScore(
                    parsedAttestation.verifiedBootState,
                    true,
                    parsedAttestation.keymasterSecurityLevel,
                    isRooted,
                    isHookDetected
            );

            String decision = "REJECT";
            boolean success = false;

            if (score >= PolicyConfig.THRESHOLD_APPROVE) {
                decision = "APPROVE";
                success = true;
            } else if (score >= PolicyConfig.THRESHOLD_REJECT) {
                decision = "REVIEW";
            }

            String sessionId = null;

            if (success) {
                sessionId = UUID.randomUUID().toString();
                AttestationEngine.sessionStore.put(
                        sessionId,
                        score);
            }

            ObjectNode responseJson =
                    mapper.createObjectNode();

            responseJson.put("success", success);
            responseJson.put("decision", decision);
            responseJson.put("trustScore", score);
            responseJson.put("sessionId", sessionId);

            responseJson.put(
                    "verifiedBootState",
                    parsedAttestation.verifiedBootState);

            responseJson.put(
                    "bootloaderLocked",
                    parsedAttestation.isBootloaderLocked);

            responseJson.put(
                    "attestationSecurityLevel",
                    parsedAttestation.attestationSecurityLevel);

            responseJson.put(
                    "keymasterSecurityLevel",
                    parsedAttestation.keymasterSecurityLevel);

            responseJson.set("policy", STATIC_POLICY_JSON);

            out.print(
                    mapper.writeValueAsString(responseJson));

        } catch (Exception e) {

            resp.setStatus(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

            out.print(
                    "{\"success\":false,\"reason\":\"SERVER_ERROR\",\"message\":\""
                            + e.getMessage()
                            + "\"}");
        }
    }
}