/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.models.binding;

import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
@Table(schema="insurance_policy_binding",name="operation")
public record PolicyBindingOperation(@Id UUID operationId,UUID tenantId,String ownerIssuer,String ownerSubject,String ownerClientId,String ownerPlatformTenant,UUID processId,UUID correlationId,
        UUID actionId,String operation,String intentDigest,UUID policyId,UUID receiptId,UUID eventId,String evidenceDigest,UUID configurationBindingId,long configurationBindingVersion,String configurationBindingDigest,String authorizationPolicyRevision,String authorizationDecisionId,
        String admissionPolicyRevision,String admissionDecisionId,String decisionEvidenceDigest) {
    @Override public String toString(){return "PolicyBindingOperation[redacted]";}
}
