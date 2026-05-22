const express = require("express");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");
const { Certificate } = require("@fidm/x509");

const app = express();
app.use(bodyParser.json({ limit: "10mb" }));

// =====================================================
// MEMORY STORES (replace with Redis in production)
// =====================================================
const nonceStore = new Map();   // nonce -> timestamp
const usedNonceStore = new Set(); // replay protection
const sessionStore = new Map(); // device sessions

// =====================================================
// CONFIG (MPoC POLICY ENGINE)
// =====================================================
const POLICY = {
    maxNonceAgeMs: 2 * 60 * 1000, // 2 minutes
    weights: {
        verifiedBoot: 40,
        rootOfTrust: 25,
        keymaster: 20,
        rootDetected: 10,
        hookDetected: 5
    },
    thresholds: {
        approve: 75,
        reject: 60
    }
};

const ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

// =====================================================
// BACKEND ASN.1 / X509 ATTESTATION PARSER
// =====================================================
function parseAndroidAttestation(base64Cert) {
    try {
        const certBuffer = Buffer.from(base64Cert, "base64");
        
        const pemString = [
            '-----BEGIN CERTIFICATE-----',
            certBuffer.toString('base64').match(/.{1,64}/g).join('\n'),
            '-----END CERTIFICATE-----'
        ].join('\n');

        const x509 = Certificate.fromPEM(Buffer.from(pemString));
        const ext = x509.extensions.find(e => e.oid === ATTESTATION_OID);
        if (!ext) {
            console.warn("Attestation extension OID not found inside X509 components.");
            return null;
        }

        const extValueBytes = ext.value; 

        let attestationLevel = "UNKNOWN";
        let keymasterLevel = "UNKNOWN";
        let hardwareBootloaderLocked = false;
        let hardwareVerifiedBootState = "UNKNOWN";

        if (extValueBytes && extValueBytes.length > 4) {
            let cursor = 0;
            if (extValueBytes[cursor] === 0x30) {
                cursor++;
                if (extValueBytes[cursor] & 0x80) {
                    cursor += 1 + (extValueBytes[cursor] & 0x7F);
                } else {
                    cursor++;
                }
            }

            // 1. Extract attestationVersion
            if (extValueBytes[cursor] === 0x02) { 
                cursor += 2 + extValueBytes[cursor + 1]; 
            }
            // 2. Extract attestationSecurityLevel
            if (extValueBytes[cursor] === 0x0a || extValueBytes[cursor] === 0x02) {
                const val = extValueBytes[cursor + 2];
                attestationLevel = (val === 1) ? "TRUSTED_ENVIRONMENT" : (val === 2) ? "STRONGBOX" : "SOFTWARE";
                cursor += 2 + extValueBytes[cursor + 1];
            }
            // 3. Extract keymasterVersion
            if (extValueBytes[cursor] === 0x02) { 
                cursor += 2 + extValueBytes[cursor + 1]; 
            }
            // 4. Extract keymasterSecurityLevel
            if (extValueBytes[cursor] === 0x0a || extValueBytes[cursor] === 0x02) {
                const val = extValueBytes[cursor + 2];
                keymasterLevel = (val === 1) ? "TRUSTED_ENVIRONMENT" : (val === 2) ? "STRONGBOX" : "SOFTWARE";
            }

            // =================================================================
            // MULTI-FLAVOR SIGNATURE SCAN FOR ROOT OF TRUST (TAG 704)
            // =================================================================
            let rotCursor = -1;
            let rotLen = 0;

            for (let i = 0; i < extValueBytes.length - 4; i++) {
                // Flavor A: Standard ASN.1 Long-Form Identifier (0xBF 0x85 0x40)
                if (extValueBytes[i] === 0xBF && extValueBytes[i+1] === 0x85 && extValueBytes[i+2] === 0x40) {
                    let lenByte = extValueBytes[i + 3];
                    let headerOffset = 4;
                    if (lenByte & 0x80) {
                        headerOffset += (lenByte & 0x7F);
                    }
                    // Confirm it wraps an inner ASN.1 Sequence (0x30)
                    if (extValueBytes[i + headerOffset] === 0x30) {
                        rotCursor = i + headerOffset;
                        rotLen = extValueBytes[rotCursor + 1];
                        break;
                    }
                }
                // Flavor B: Short-Form/Alternative Packing Sequence Header (0xA4)
                if (extValueBytes[i] === 0xA4 && extValueBytes[i + 2] === 0x30) {
                    rotCursor = i + 2;
                    rotLen = extValueBytes[rotCursor + 1];
                    break;
                }
            }

            if (rotCursor !== -1) {
                // Adjust for sequence wrapper length bytes
                if (rotLen & 0x80) {
                    const lengthBytesCount = rotLen & 0x7F;
                    rotCursor += 2 + lengthBytesCount;
                } else {
                    rotCursor += 2;
                }

                // Scan inside the isolated RootOfTrust payload bounding window
                let scanLimit = rotCursor + 64; 
                if (scanLimit > extValueBytes.length) scanLimit = extValueBytes.length;

                while (rotCursor < scanLimit) {
                    const tag = extValueBytes[rotCursor];
                    const len = extValueBytes[rotCursor + 1];

                    if (len === undefined || rotCursor + 2 + len > extValueBytes.length) break;

                    // Tag 0x01 = deviceLocked (Boolean)
                    if (tag === 0x01) {
                        hardwareBootloaderLocked = extValueBytes[rotCursor + 2] !== 0x00;
                    }

                    // Tag 0x0A = verifiedBootState (Enumerated)
                    if (tag === 0x0a) {
                        const bootStateVal = extValueBytes[rotCursor + 2];
                        console.log("--> Intercepted Verified Boot State Value:", bootStateVal);
                        const states = ["VERIFIED", "SELF_SIGNED", "UNVERIFIED", "FAILED"];
                        hardwareVerifiedBootState = states[bootStateVal] || "UNKNOWN";
                    }

                    rotCursor += 2 + len;
                    if (tag === 0x00) break;
                }
            } else {
                console.warn("CRITICAL: Root of Trust structural sequence signature not found in this hardware payload.");
            }
        }

        return {
            isValidChainElement: true,
            attestationSecurityLevel: attestationLevel,
            keymasterSecurityLevel: keymasterLevel,
            isBootloaderLocked: hardwareBootloaderLocked,
            verifiedBootState: hardwareVerifiedBootState
        };
    } catch (e) {
        console.error("Cryptographic hardware block verification failure:", e);
        return null;
    }
}

function computeTrustScore(data) {
    let score = 0;

    // 1. Verified Boot
    if (data.verifiedBootState === "VERIFIED") {
        score += POLICY.weights.verifiedBoot;
    }

    // 2. Bootloader / RootOfTrust
    if (data.isBootloaderLocked === true) {
        score += POLICY.weights.rootOfTrust;
    }

    // 3. Keymaster level
    if (data.keymasterSecurityLevel === "TRUSTED_ENVIRONMENT" || data.keymasterSecurityLevel === "STRONGBOX") {
        score += POLICY.weights.keymaster;
    }

    // 4. Root detection
    if (!data.isRooted) {
        score += POLICY.weights.rootDetected;
    }

    // 5. Hook detection
    if (!data.isHookDetected) {
        score += POLICY.weights.hookDetected;
    }

    return score;
}

// =====================================================
// UTIL: NONCE GENERATION
// =====================================================
app.get("/nonce", (req, res) => {
    const nonce = crypto.randomBytes(32).toString("hex");
    nonceStore.set(nonce, Date.now());
    res.json({
        nonce,
        expiresIn: POLICY.maxNonceAgeMs
    });
});

// =====================================================
// VERIFY NONCE (REPLAY PROTECTION)
// =====================================================
function verifyNonce(nonce) {
    if (!nonceStore.has(nonce)) {
        return { valid: false, reason: "UNKNOWN_NONCE" };
    }
    if (usedNonceStore.has(nonce)) {
        return { valid: false, reason: "REPLAY_DETECTED" };
    }

    const createdAt = nonceStore.get(nonce);
    const now = Date.now();

    if (now - createdAt > POLICY.maxNonceAgeMs) {
        return { valid: false, reason: "NONCE_EXPIRED" };
    }

    usedNonceStore.add(nonce);
    nonceStore.delete(nonce);
    return { valid: true };
}

// =====================================================
// ATTESTATION ENDPOINT
// =====================================================
app.post("/attest", (req, res) => {
    const { nonce, certificateChain } = req.body;

    // 1. NONCE VALIDATION
    const nonceCheck = verifyNonce(nonce);
    if (!nonceCheck.valid) {
        return res.status(403).json({ success: false, reason: nonceCheck.reason });
    }

    // 2. CERTIFICATE CHAIN STRUCTURAL BACKEND VERIFICATION
    if (!Array.isArray(certificateChain) || certificateChain.length === 0) {
        return res.status(400).json({ success: false, reason: "INVALID_CERT_CHAIN" });
    }

    const parsedAttestation = parseAndroidAttestation(certificateChain[0]);
    console.log("Parsed Hardware Attestation Output:", parsedAttestation);
    if (!parsedAttestation) {
        return res.status(400).json({ success: false, reason: "CRYPTO_PARSING_FAILED" });
    }

    // 3. OVERRIDE AND ENFORCE VERIFIED CERTIFICATE STATE
    const trustData = {
        isRooted: req.body.isRooted,
        isHookDetected: req.body.isHookDetected,
        isBootloaderLocked: parsedAttestation.isBootloaderLocked, 
        verifiedBootState: parsedAttestation.verifiedBootState,   
        attestationSecurityLevel: parsedAttestation.attestationSecurityLevel,
        keymasterSecurityLevel: parsedAttestation.keymasterSecurityLevel
    };

    console.log("Final Trust Engine Inputs:", trustData);

    const score = computeTrustScore(trustData);

    // 4. DECISION ENGINE
    let decision = "REJECT";
    let success = false;

    if (score >= POLICY.thresholds.approve) {
        decision = "APPROVE";
        success = true;
    } else if (score >= POLICY.thresholds.reject) {
        decision = "REVIEW";
    }

    // 5. SESSION ALLOCATION
    const sessionId = uuidv4();
    if (success) {
        sessionStore.set(sessionId, {
            createdAt: Date.now(),
            score
        });
    }

    res.json({
        success,
        decision,
        trustScore: score,
        sessionId: success ? sessionId : null,
        policy: POLICY
    });
});

// =====================================================
// START UP SERVICE
// =====================================================
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`MPoC Attestation Backend running on port ${PORT}`);
});