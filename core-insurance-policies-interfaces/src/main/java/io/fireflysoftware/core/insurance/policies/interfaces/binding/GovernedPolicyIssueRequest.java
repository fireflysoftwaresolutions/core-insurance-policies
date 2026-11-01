/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import java.util.UUID;
@io.swagger.v3.oas.annotations.media.Schema(requiredProperties={"actionId","expectedBindingVersion","bindingReceiptDigest"})
public record GovernedPolicyIssueRequest(UUID actionId,long expectedBindingVersion,String bindingReceiptDigest) {
    public GovernedPolicyIssueRequest {PolicyBindingValues.id(actionId);PolicyBindingValues.digest(bindingReceiptDigest);if(expectedBindingVersion<1)throw new IllegalArgumentException("Existing bound policy version required");}
    public String intentDigest(UUID policyId){PolicyBindingValues.id(policyId);return PolicyBindingValues.hash("CORE_POLICY_ISSUE_V1",actionId.toString(),policyId.toString(),Long.toString(expectedBindingVersion),bindingReceiptDigest);}
    @Override public String toString(){return "GovernedPolicyIssueRequest[redacted]";}
}
