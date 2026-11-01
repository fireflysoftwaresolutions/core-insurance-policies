/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.models.binding;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
@Table(schema="insurance_policy_binding",name="binding")
public record PolicyBindingSnapshot(@Id UUID policyId,UUID tenantId,String ownerIssuer,String ownerSubject,
        UUID submissionId,UUID partyId,UUID productId,UUID contractId,String policyNumber,String currency,
        LocalDate inceptionDate,LocalDate expiryDate,UUID offerId,long offerVersion,long acceptedControlGeneration,
        UUID acceptanceActionId,UUID acceptanceId,String acceptanceIntentDigest,String termsDigest,java.time.Instant acceptedAt,String quoteSnapshotDigest,UUID productRevisionId,
        String productDigest,String riskDigest,String providerVersion,String ruleSetVersion,BigDecimal basePremium,
        BigDecimal tax,BigDecimal fees,String coverageTermsJson,String state,long bindingVersion,String bindingReceiptDigest,
        UUID boundEventId,UUID activeEventId) {
    @Override public String toString(){return "PolicyBindingSnapshot[redacted]";}
}
