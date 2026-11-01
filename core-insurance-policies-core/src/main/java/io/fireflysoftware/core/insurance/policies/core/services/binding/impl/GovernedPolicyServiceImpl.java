/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import reactor.core.publisher.Mono;

/** Remote read preparation is outside the Core write root; uncertain writes retain their original identity. */
public final class GovernedPolicyServiceImpl implements GovernedPolicyService {
    private final PolicyBindingAdmission authority;
    private final AcceptedQuotePort quotes;
    private final PolicyContractPort contracts;
    private final PolicyBindingStore store;
    private final Clock clock;
    private final java.util.function.LongSupplier nanos;
    public GovernedPolicyServiceImpl(PolicyBindingAdmission authority,AcceptedQuotePort quotes,PolicyContractPort contracts,PolicyBindingStore store,Clock clock){
        this.authority=Objects.requireNonNull(authority);this.quotes=Objects.requireNonNull(quotes);this.contracts=Objects.requireNonNull(contracts);
        this.store=Objects.requireNonNull(store);this.clock=Objects.requireNonNull(clock);this.nanos=System::nanoTime;
    }
    @Override public Mono<GovernedPolicyCommandResponse> bind(GovernedPolicyBindRequest request){return Mono.defer(()->{
        Objects.requireNonNull(request);String digest=request.intentDigest();
        return current(PolicyBindingAdmission.Request.bind(request))
            .flatMap(permit->Mono.defer(()->quotes.observe(permit,request)).timeout(permit.remaining(clock,nanos)).switchIfEmpty(Mono.error(new PolicyBindingRefusedException()))
                .flatMap(quote->{quote.requireMatch(permit,request);return Mono.defer(()->contracts.requireExisting(permit,request,quote)).timeout(permit.remaining(clock,nanos))
                    .then(revalidate(permit,PolicyBindingAdmission.Action.BIND,request.actionId(),digest)).thenReturn(quote);})
                .onErrorMap(error->error instanceof GovernedPolicyUnavailableException?error:new PolicyBindingRefusedException())
                .flatMap(quote->write(permit,PolicyBindingAdmission.Action.BIND,request.actionId(),digest,
                    ()->store.bind(permit,request,quote)))).onErrorResume(PolicyBindingRefusedException.class,error->Mono.just(new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.REFUSED,request.actionId(),digest,null)));
    });}
    @Override public Mono<GovernedPolicyCommandResponse> issue(UUID policyId,GovernedPolicyIssueRequest request){return Mono.defer(()->{
        Objects.requireNonNull(request);String digest=request.intentDigest(policyId);
        return current(new PolicyBindingAdmission.Request(PolicyBindingAdmission.Action.ISSUE,request.actionId(),digest,policyId,null,null,null,null)).flatMap(permit->
            write(permit,PolicyBindingAdmission.Action.ISSUE,request.actionId(),digest,()->store.issue(permit,policyId,request)));
    });}
    @Override public Mono<GovernedPolicyRecoveryResponse> recover(UUID actionId,String digest){return Mono.defer(()->{
        PolicyBindingValues.id(actionId);PolicyBindingValues.digest(digest);
        return current(new PolicyBindingAdmission.Request(PolicyBindingAdmission.Action.RECOVER,actionId,digest,null,null,null,null,null)).flatMap(permit->store.recover(permit,actionId,digest)
            .switchIfEmpty(Mono.error(unavailable())).flatMap(value->{
                if(!actionId.equals(value.actionId()) || !digest.equals(value.intentDigest()))return Mono.error(unavailable());
                return revalidate(permit,PolicyBindingAdmission.Action.RECOVER,actionId,digest).thenReturn(value);
            }));
    });}
    private Mono<PolicyBindingAdmission.Permit> current(PolicyBindingAdmission.Request request){
        return Mono.defer(()->authority.requireCurrent(request)).switchIfEmpty(Mono.error(unavailable()))
            .map(p->{if(!request.equals(p.request()))throw unavailable();live(p);return p;});
    }
    private Mono<Void> revalidate(PolicyBindingAdmission.Permit p,PolicyBindingAdmission.Action action,UUID id,String digest){
        return Mono.defer(()->{live(p);return authority.revalidate(p).timeout(p.remaining(clock,nanos));}).then(Mono.fromRunnable(()->live(p)));
    }
    private Mono<GovernedPolicyCommandResponse> write(PolicyBindingAdmission.Permit p,PolicyBindingAdmission.Action action,UUID id,String digest,
            Supplier<Mono<GovernedPolicyCommandResponse>> writing){
        return Mono.defer(writing).switchIfEmpty(Mono.error(new IllegalStateException("Missing policy root completion")))
            .flatMap(value->{
                if(!id.equals(value.actionId()) || !digest.equals(value.intentDigest()))return Mono.error(new IllegalStateException("Policy root identity changed"));
                if(value.status()!=GovernedPolicyCommandResponse.Status.COMMITTED)return Mono.just(value);
                return revalidate(p,action,id,digest).thenReturn(value).onErrorReturn(
                    new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.COMMITTED_RESPONSE_UNAVAILABLE,id,digest,null));
            }).onErrorResume(PolicyBindingWriteFailure.class,error->Mono.just(new GovernedPolicyCommandResponse(error.status(),id,digest,null)))
            .onErrorReturn(new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.OUTCOME_UNKNOWN,id,digest,null));
    }
    private void live(PolicyBindingAdmission.Permit p){p.remaining(clock,nanos);}
    private static GovernedPolicyUnavailableException unavailable(){return new GovernedPolicyUnavailableException();}
}
