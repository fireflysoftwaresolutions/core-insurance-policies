/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.contract.sdk.model.*;
import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest;
import java.time.Clock;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/** Data checks do not establish a multitenant owner contract; the explicit dedicated deployment binding is mandatory. */
public final class GeneratedSdkPolicyContractPortImpl implements PolicyContractPort {
    private final PolicyContractClientProvider clients;
    private final Clock clock;
    public GeneratedSdkPolicyContractPortImpl(PolicyContractClientProvider clients,Clock clock){this.clients=Objects.requireNonNull(clients);this.clock=Objects.requireNonNull(clock);}
    @Override public Mono<Void> requireExisting(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request,AcceptedQuoteEvidence quote){return Mono.defer(()->
        clients.requireCurrent(permit).switchIfEmpty(Mono.error(new GovernedPolicyUnavailableException())).flatMap(current->{
            binding(permit,current);var role=current.binding().policyholderRoleId();
            var filter=new FilterRequestContractPartyDTO().filters(new ContractPartyDTO().contractId(request.contractId()).partyId(request.partyId()).roleInContractId(role).isActive(true))
                .pagination(new PaginationRequest().pageNumber(0).pageSize(2).sortBy("contractPartyId").sortDirection("ASC"));
            return Mono.zip(current.contracts().getContractByIdWithHttpInfo(request.contractId(),null),current.parties().filterContractPartiesWithHttpInfo(request.contractId(),filter))
                .timeout(permit.remaining(clock,System::nanoTime)).switchIfEmpty(Mono.error(refused())).flatMap(pair->{
                    binding(permit,current);
                    if(pair.getT1().getStatusCode().value()!=200 || pair.getT2().getStatusCode().value()!=200)return Mono.error(refused());
                    var contract=pair.getT1().getBody();var page=pair.getT2().getBody();
                    if(contract==null || page==null || !request.contractId().equals(contract.getContractId()) || !request.productId().equals(contract.getProductId())
                        || !quote.currency().equals(contract.getCurrencyCode()) || contract.getContractStatus()!=ContractDTO.ContractStatusEnum.ACTIVE
                        || contract.getStartDate()==null || contract.getEndDate()==null || request.inceptionDate().atStartOfDay().isBefore(contract.getStartDate())
                        || request.expiryDate().atStartOfDay().isAfter(contract.getEndDate()) || page.getCurrentPage()==null || page.getCurrentPage()!=0
                        || page.getTotalPages()==null || page.getTotalPages()!=1 || page.getTotalElements()==null || page.getTotalElements()!=1
                        || page.getContent()==null || page.getContent().size()!=1)return Mono.error(refused());
                    ContractPartyDTO party=page.getContent().getFirst();
                    if(party==null
                        || party.getContractPartyId()==null || !request.contractId().equals(party.getContractId()) || !request.partyId().equals(party.getPartyId())
                        || !role.equals(party.getRoleInContractId()) || !Boolean.TRUE.equals(party.getIsActive()) || party.getDateJoined()==null
                        || request.inceptionDate().atStartOfDay().isBefore(party.getDateJoined())
                        || party.getDateLeft()!=null && request.expiryDate().atStartOfDay().isAfter(party.getDateLeft()))return Mono.error(refused());
                    return Mono.<Void>empty();
                });
        })).onErrorMap(error->{
            if(error instanceof PolicyBindingRefusedException || error instanceof GovernedPolicyUnavailableException)return error;
            if(error instanceof WebClientResponseException response && (response.getStatusCode().value()==401 || response.getStatusCode().value()==403))
                return new ResponseStatusException(HttpStatus.FORBIDDEN,"Owned contract observation refused");
            return new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Owned contract observation unavailable");
        });}
    private void binding(PolicyBindingAdmission.Permit permit,PolicyContractClientProvider.Clients current){
        permit.remaining(clock,System::nanoTime);var binding=current.binding();String endpoint=binding.endpoint().toASCIIString();
        if(!permit.resourceTenantId().equals(binding.resourceTenantId()) || !permit.bindingId().equals(binding.configurationBindingId())
                || permit.bindingVersion()!=binding.configurationBindingVersion() || !permit.bindingDigest().equals(binding.configurationBindingDigest())
                || permit.notAfter().isAfter(binding.notAfter()) || !endpoint.equals(current.contracts().getApiClient().getBasePath())
                || current.contracts().getApiClient()!=current.parties().getApiClient())throw refused();
    }
    private static PolicyBindingRefusedException refused(){return new PolicyBindingRefusedException();}
}
