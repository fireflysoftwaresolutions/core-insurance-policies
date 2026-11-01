/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.contract.sdk.api.ContractsApi;
import io.fireflysoftware.core.contract.sdk.api.ContractPartiesApi;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.PolicyBindingValues;
import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Trusted server-owned dedicated dataset binding; this is not a tenant claim inferred from ContractDTO. */
public interface PolicyContractClientProvider {
    record ServerBinding(UUID resourceTenantId,UUID configurationBindingId,long configurationBindingVersion,
            String configurationBindingDigest,URI endpoint,UUID policyholderRoleId,Instant notAfter){
        public ServerBinding {PolicyBindingValues.id(resourceTenantId);PolicyBindingValues.id(configurationBindingId);
            PolicyBindingValues.digest(configurationBindingDigest);PolicyBindingValues.id(policyholderRoleId);Objects.requireNonNull(notAfter);
            if(configurationBindingVersion<1 || endpoint==null || !"https".equals(endpoint.getScheme()) || endpoint.getHost()==null
                || endpoint.getUserInfo()!=null || endpoint.getQuery()!=null || endpoint.getFragment()!=null)throw new GovernedPolicyUnavailableException();}
        @Override public String toString(){return "SingleTenantContractServerBinding[redacted]";}
    }
    record Clients(ServerBinding binding,ContractsApi contracts,ContractPartiesApi parties){
        public Clients {Objects.requireNonNull(binding);Objects.requireNonNull(contracts);Objects.requireNonNull(parties);
            if(contracts.getApiClient()!=parties.getApiClient())throw new GovernedPolicyUnavailableException();}
        @Override public String toString(){return "PolicyContractClients[redacted]";}
    }
    /** Must use the qualified actual generated authenticated transport, with a fresh client bound to this caller. */
    Mono<Clients> requireCurrent(PolicyBindingAdmission.Permit original);
}
