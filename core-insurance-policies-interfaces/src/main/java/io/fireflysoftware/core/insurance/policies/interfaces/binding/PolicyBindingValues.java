/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

public final class PolicyBindingValues {
    private PolicyBindingValues() {}
    public static UUID id(UUID value) {Objects.requireNonNull(value);if(value.equals(new UUID(0,0)))throw invalid();return value;}
    public static String digest(String value) {if(value==null || !value.matches("[0-9a-f]{64}"))throw invalid();return value;}
    public static String text(String value,int maxBytes) {
        Objects.requireNonNull(value);
        try {
            ByteBuffer bytes=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
            if(value.isBlank() || bytes.remaining()>maxBytes || value.codePoints().anyMatch(Character::isISOControl))throw invalid();
            return value;
        } catch(java.nio.charset.CharacterCodingException e) {throw invalid();}
    }
    public static String hash(String... fields) {
        try {
            var bytes=new ByteArrayOutputStream();var output=new DataOutputStream(bytes);
            for(String field:fields){byte[] encoded=text(field,4096).getBytes(StandardCharsets.UTF_8);output.writeInt(encoded.length);output.write(encoded);}
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
        }catch(java.io.IOException|java.security.NoSuchAlgorithmException e){throw new IllegalStateException("Policy identity unavailable");}
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Exact governed policy identity required");}
}
