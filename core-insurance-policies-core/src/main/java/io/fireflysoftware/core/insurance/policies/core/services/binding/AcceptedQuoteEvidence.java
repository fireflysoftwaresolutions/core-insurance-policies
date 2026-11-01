/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A protected owner observation, not authority derived from a request body. */
public record AcceptedQuoteEvidence(UUID tenantId,UUID submissionId,UUID partyId,UUID productId,UUID offerId,
        long offerVersion,long controlGeneration,UUID acceptanceActionId,UUID acceptanceId,String acceptanceIntentDigest,
        String termsDigest,String currency,BigDecimal basePremium,BigDecimal tax,BigDecimal fees,
        java.util.Map<String,String> coverageTerms,UUID productRevisionId,String productDigest,String riskDigest,
        String providerVersion,String ruleSetVersion,Instant acceptedAt,String ownerIssuer,String ownerSubject) {
    public AcceptedQuoteEvidence {
        for(UUID value:new UUID[]{tenantId,submissionId,partyId,productId,offerId,acceptanceActionId,acceptanceId})PolicyBindingValues.id(value);
        PolicyBindingValues.digest(acceptanceIntentDigest);PolicyBindingValues.digest(termsDigest);
        if(offerVersion<1 || controlGeneration<1 || currency==null || !currency.matches("[A-Z]{3}"))throw invalid();
        Objects.requireNonNull(basePremium);Objects.requireNonNull(tax);Objects.requireNonNull(fees);
        try{basePremium=basePremium.setScale(2,java.math.RoundingMode.UNNECESSARY);tax=tax.setScale(2,java.math.RoundingMode.UNNECESSARY);fees=fees.setScale(2,java.math.RoundingMode.UNNECESSARY);}catch(ArithmeticException error){throw invalid();}
        if(!"USD".equals(currency) || basePremium.signum()<=0 || tax.signum()<0 || fees.signum()<0 || basePremium.precision()>19 || tax.precision()>19 || fees.precision()>19)throw invalid();
        Objects.requireNonNull(coverageTerms);if(coverageTerms.isEmpty() || coverageTerms.size()>32)throw invalid();
        var terms=new java.util.TreeMap<String,String>();int total=0;
        for(var entry:coverageTerms.entrySet()){String key=PolicyBindingValues.text(entry.getKey(),64);if(!key.matches("[a-z][a-zA-Z0-9._-]{0,63}"))throw invalid();String value=PolicyBindingValues.text(entry.getValue(),4096);
            total+=key.getBytes(java.nio.charset.StandardCharsets.UTF_8).length+value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;terms.put(key,value);}
        if(total>32768)throw invalid();coverageTerms=java.util.Collections.unmodifiableMap(terms);
        PolicyBindingValues.id(productRevisionId);PolicyBindingValues.digest(productDigest);PolicyBindingValues.digest(riskDigest);
        providerVersion=PolicyBindingValues.text(providerVersion,128);ruleSetVersion=PolicyBindingValues.text(ruleSetVersion,128);Objects.requireNonNull(acceptedAt);if(acceptedAt.getNano()%1000!=0)throw invalid();
        ownerIssuer=PolicyBindingValues.text(ownerIssuer,512);ownerSubject=PolicyBindingValues.text(ownerSubject,255);
    }
    public void requireMatch(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest r){
        if(!tenantId.equals(permit.resourceTenantId()) || !submissionId.equals(r.submissionId()) || !partyId.equals(r.partyId()) || !partyId.equals(permit.partyId())
                || !productId.equals(r.productId()) || !offerId.equals(r.offerId()) || offerVersion!=r.offerVersion()
                || controlGeneration!=r.acceptedControlGeneration() || !acceptanceActionId.equals(r.acceptanceActionId())
                || !acceptanceIntentDigest.equals(r.acceptanceIntentDigest()) || !termsDigest.equals(r.termsDigest())
                || !"firefly-sandbox-property-1".equals(providerVersion) || !"illustrative-property-1".equals(ruleSetVersion)
                || !"SANDBOX_PROPERTY_DAMAGE".equals(coverageTerms.get("coverageCode"))
                || !r.inceptionDate().toString().equals(coverageTerms.get("coverageStart"))
                || !r.expiryDate().toString().equals(coverageTerms.get("coverageEnd"))
                || !ownerIssuer.equals(permit.actor().issuer()) || !ownerSubject.equals(permit.actor().subject()))throw invalid();
    }
    public String snapshotDigest(){
        var values=new java.util.ArrayList<String>(java.util.List.of("CORE_ACCEPTED_QUOTE_SNAPSHOT_V1",tenantId.toString(),submissionId.toString(),partyId.toString(),productId.toString(),offerId.toString(),Long.toString(offerVersion),Long.toString(controlGeneration),acceptanceActionId.toString(),acceptanceId.toString(),acceptanceIntentDigest,termsDigest,currency,basePremium.toPlainString(),tax.toPlainString(),fees.toPlainString(),productRevisionId.toString(),productDigest,riskDigest,providerVersion,ruleSetVersion,acceptedAt.toString(),ownerIssuer,ownerSubject));
        coverageTerms.forEach((key,value)->{values.add(key);values.add(value);});return PolicyBindingValues.hash(values.toArray(String[]::new));
    }
    private static PolicyBindingRefusedException invalid(){return new PolicyBindingRefusedException();}
    @Override public String toString(){return "AcceptedQuoteEvidence[redacted]";}
}
