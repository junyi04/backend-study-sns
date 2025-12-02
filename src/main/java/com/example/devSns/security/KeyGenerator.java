package com.example.devSns.security;

import java.security.SecureRandom;
import java.util.Base64;

public class KeyGenerator {
    public static void main(String[] args) {
        // 무작위 키 생성
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[64];
        secureRandom.nextBytes(keyBytes);

        String base64Key = Base64.getEncoder().encodeToString(keyBytes);

        System.out.println("생성된 JWT Secret Key (Base64):");
        System.out.println(base64Key);
    }
}