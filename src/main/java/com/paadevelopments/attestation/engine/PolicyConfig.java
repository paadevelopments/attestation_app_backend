package com.paadevelopments.attestation.engine;

public final class PolicyConfig {

    // Prevent instantiation of utility class
    private PolicyConfig() {}

    // =====================================================
    // MPoC SECURITY WEIGHTS
    // =====================================================
    public static final int WEIGHT_VERIFIED_BOOT = 40;
    public static final int WEIGHT_ROOT_OF_TRUST = 25;
    public static final int WEIGHT_KEYMASTER     = 20;
    public static final int WEIGHT_ROOT_DETECTED = 10;
    public static final int WEIGHT_HOOK_DETECTED = 5;

    // =====================================================
    // DECISION ENGINE THRESHOLDS
    // =====================================================
    public static final int THRESHOLD_APPROVE = 75;
    public static final int THRESHOLD_REJECT  = 60;
}