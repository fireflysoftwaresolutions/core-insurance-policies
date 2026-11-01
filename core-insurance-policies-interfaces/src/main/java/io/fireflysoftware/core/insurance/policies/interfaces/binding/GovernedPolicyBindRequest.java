/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import java.time.LocalDate;
import java.util.Objects;
import java.util.UUID;

/** Selectors establish intent only; Core obtains authority and accepted terms independently. */
@io.swagger.v3.oas.annotations.media.Schema(requiredProperties={"actionId","submissionId","partyId","productId","offerId","offerVersion","acceptedControlGeneration","acceptanceActionId","acceptanceIntentDigest","termsDigest","contractId","policyNumber","inceptionDate","expiryDate"})
public record GovernedPolicyBindRequest(UUID actionId,UUID submissionId,UUID partyId,UUID productId,
        UUID offerId,long offerVersion,long acceptedControlGeneration,UUID acceptanceActionId,
        String acceptanceIntentDigest,String termsDigest,UUID contractId,String policyNumber,
        LocalDate inceptionDate,LocalDate expiryDate) {
    public GovernedPolicyBindRequest {
        PolicyBindingValues.id(actionId);PolicyBindingValues.id(submissionId);PolicyBindingValues.id(partyId);
        PolicyBindingValues.id(productId);PolicyBindingValues.id(offerId);PolicyBindingValues.id(acceptanceActionId);
        PolicyBindingValues.id(contractId);PolicyBindingValues.digest(acceptanceIntentDigest);PolicyBindingValues.digest(termsDigest);
        policyNumber=PolicyBindingValues.text(policyNumber,64);Objects.requireNonNull(inceptionDate);Objects.requireNonNull(expiryDate);
        if(offerVersion<1 || acceptedControlGeneration<1 || inceptionDate.getYear()<1 || expiryDate.getYear()>9999 || !expiryDate.isAfter(inceptionDate))throw new IllegalArgumentException("Exact policy version and coverage dates required");
    }
    public String intentDigest(){return PolicyBindingValues.hash("CORE_POLICY_BIND_V1",actionId.toString(),submissionId.toString(),partyId.toString(),productId.toString(),offerId.toString(),Long.toString(offerVersion),Long.toString(acceptedControlGeneration),acceptanceActionId.toString(),acceptanceIntentDigest,termsDigest,contractId.toString(),policyNumber,inceptionDate.toString(),expiryDate.toString());}
    @Override public String toString(){return "GovernedPolicyBindRequest[redacted]";}
}
