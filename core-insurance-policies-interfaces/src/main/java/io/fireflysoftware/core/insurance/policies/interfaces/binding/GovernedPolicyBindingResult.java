/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.enums.PolicyStatus;
import java.util.Objects;
import java.util.UUID;

/** Core receipt; IN_FORCE is local activation, never carrier/provider issuance. */
@io.swagger.v3.oas.annotations.media.Schema(requiredProperties={"policyId","policyNumber","policyStatus","bindingVersion","bindingReceiptDigest","acceptanceActionId","acceptanceId","offerId","offerVersion","termsDigest"})
public record GovernedPolicyBindingResult(UUID policyId,String policyNumber,PolicyStatus policyStatus,
        long bindingVersion,String bindingReceiptDigest,UUID acceptanceActionId,UUID acceptanceId,
        UUID offerId,long offerVersion,String termsDigest) {
    public GovernedPolicyBindingResult {
        PolicyBindingValues.id(policyId);policyNumber=PolicyBindingValues.text(policyNumber,64);Objects.requireNonNull(policyStatus);
        PolicyBindingValues.digest(bindingReceiptDigest);PolicyBindingValues.id(acceptanceActionId);PolicyBindingValues.id(acceptanceId);
        PolicyBindingValues.id(offerId);PolicyBindingValues.digest(termsDigest);
        if(bindingVersion<1 || offerVersion<1 || policyStatus!=PolicyStatus.BOUND && policyStatus!=PolicyStatus.IN_FORCE)throw new IllegalArgumentException("Exact committed governed policy receipt required");
    }
    @Override public String toString(){return "GovernedPolicyBindingResult[redacted]";}
}
