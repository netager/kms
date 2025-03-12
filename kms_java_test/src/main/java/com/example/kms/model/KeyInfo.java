package com.example.kms.model;

import java.time.LocalDateTime;

public record KeyInfo(
    int keyId,
    String keyMaterial,
    String salt,
    int version,
    LocalDateTime lastUpdated
) {} 