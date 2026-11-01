/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest;
import io.fireflysoftware.core.insurance.underwriting.sdk.model.*;
import java.time.ZoneOffset;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/** Uses only official generated current/recovery operations; request selectors never become receipt authority. */
public final class GeneratedSdkAcceptedQuotePortImpl implements AcceptedQuotePort {
    private final AcceptedQuoteClientProvider clients;
    public GeneratedSdkAcceptedQuotePortImpl(AcceptedQuoteClientProvider clients){this.clients=Objects.requireNonNull(clients);}
    @Override public Mono<AcceptedQuoteEvidence> observe(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request){return Mono.defer(()->
        clients.requireExchangedClient(permit).switchIfEmpty(Mono.error(new GovernedPolicyUnavailableException())).flatMap(client->
            Mono.zip(client.currentWithHttpInfo(permit.resourceTenantId(),request.submissionId(),request.partyId(),request.productId(),request.offerId()),
                client.recoverWithHttpInfo(permit.resourceTenantId(),request.submissionId(),request.partyId(),request.productId(),request.acceptanceActionId(),request.acceptanceIntentDigest()))
            .switchIfEmpty(Mono.error(new PolicyBindingRefusedException())).map(pair->{
                if(pair.getT1().getStatusCode()!=HttpStatus.OK || pair.getT2().getStatusCode()!=HttpStatus.OK)throw new PolicyBindingRefusedException();
                return observe(permit,request,pair.getT1().getBody(),pair.getT2().getBody());
            }))).onErrorMap(error->{
                if(error instanceof PolicyBindingRefusedException || error instanceof GovernedPolicyUnavailableException)return error;
                if(error instanceof WebClientResponseException response && (response.getStatusCode().value()==401 || response.getStatusCode().value()==403))
                    return new ResponseStatusException(HttpStatus.FORBIDDEN,"Protected accepted quote access refused");
                return new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Protected accepted quote observation unavailable");
            });}
    static AcceptedQuoteEvidence observe(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request,QuoteReadResponse current,QuoteRecoveryResponse recovery){
        try {
            if(current==null || recovery==null || current.getState()!=QuoteReadResponse.StateEnum.FOUND || recovery.getState()!=QuoteRecoveryResponse.StateEnum.FOUND
                || !request.acceptanceActionId().equals(recovery.getActionId()) || !request.acceptanceIntentDigest().equals(recovery.getIntentDigest()))throw new PolicyBindingRefusedException();
            var entry=Objects.requireNonNull(current.getEntry());var offer=Objects.requireNonNull(entry.getOffer());
            var receipt=Objects.requireNonNull(entry.getReceipt());var intent=Objects.requireNonNull(receipt.getIntent());
            var result=Objects.requireNonNull(recovery.getResult());var action=Objects.requireNonNull(result.getAction());
            var scope=Objects.requireNonNull(offer.getScope());var terms=Objects.requireNonNull(offer.getTerms());
            if(offer.getState()!=QuoteOfferVersion.StateEnum.ACCEPTED || action.getOperation()!=QuoteActionEnvelope.OperationEnum.ACCEPT
                || !scope.equals(intent.getScope()) || !scope.equals(action.getScope())
                || !Objects.equals(offer.getOfferId(),intent.getOfferId()) || !Objects.equals(offer.getOfferId(),action.getOfferId())
                || !Objects.equals(offer.getOfferVersion(),intent.getOfferVersion()) || !Objects.equals(offer.getOfferVersion(),action.getOfferVersion())
                || intent.getExpectedControlGeneration()==null || action.getExpectedControlGeneration()==null
                || !Objects.equals(intent.getExpectedControlGeneration(),action.getExpectedControlGeneration())
                || !Objects.equals(intent.getActionId(),action.getActionId()) || !request.acceptanceActionId().equals(action.getActionId())
                || !request.acceptanceIntentDigest().equals(action.getIntentDigest())
                || !Objects.equals(entry.getTermsDigest(),intent.getTermsDigest()) || !request.termsDigest().equals(entry.getTermsDigest())
                || receipt.getResultingControlGeneration()==null || offer.getControlGeneration()==null || result.getResultingControlGeneration()==null
                || !Objects.equals(receipt.getResultingControlGeneration(),offer.getControlGeneration())
                || !Objects.equals(receipt.getResultingControlGeneration(),result.getResultingControlGeneration())
                || receipt.getResultingControlGeneration()!=Math.addExact(intent.getExpectedControlGeneration(),1)
                || !Objects.requireNonNull(receipt.getAcceptedAt()).equals(result.getRecordedAt()))throw new PolicyBindingRefusedException();
            Objects.requireNonNull(result.getResultId());Objects.requireNonNull(result.getOfferVersionId());Objects.requireNonNull(result.getAcceptanceId());
            // The pinned original producer exposes Instant values; its selected java8-localdatetime SDK represents those UTC values without the zone.
            var observed=new AcceptedQuoteEvidence(scope.getTenantId(),scope.getSubmissionId(),scope.getPartyId(),scope.getProductId(),offer.getOfferId(),offer.getOfferVersion(),
                offer.getControlGeneration(),action.getActionId(),result.getAcceptanceId(),action.getIntentDigest(),entry.getTermsDigest(),terms.getCurrency(),terms.getBasePremium(),terms.getTax(),terms.getFees(),
                terms.getCoverageTerms(),terms.getProductRevisionId(),terms.getProductDigest(),terms.getRiskDigest(),terms.getProviderVersion(),terms.getRuleSetVersion(),receipt.getAcceptedAt().toInstant(ZoneOffset.UTC),action.getOwnerIssuer(),action.getOwnerSubject());
            observed.requireMatch(permit,request);return observed;
        }catch(NullPointerException|ArithmeticException e){throw new PolicyBindingRefusedException();}
    }
}
