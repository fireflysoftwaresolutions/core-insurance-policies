/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.models.binding;

import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
@Table(schema="insurance_policy_binding",name="receipt")
public record PolicyBindingReceipt(@Id UUID receiptId,UUID tenantId,String ownerIssuer,String ownerSubject,
        UUID operationId,UUID actionId,String intentDigest,UUID policyId,String resultJson,String resultDigest,
        UUID eventId,String eventRecordHash) {
    @Override public String toString(){return "PolicyBindingReceipt[redacted]";}
}
