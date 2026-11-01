/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding.impl;

import io.fireflysoftware.core.insurance.policies.core.services.binding.*;
import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.Supplier;
import org.fireflyframework.core.audit.AuditAppendAuthority;
import org.fireflyframework.kernel.audit.*;
import org.fireflyframework.security.api.domain.*;
import org.fireflyframework.security.spi.PolicyEvaluationPort;
import org.fireflyframework.security.spi.SecurityContextPort;
import reactor.core.publisher.Mono;

/** Explicit UUID-tenant HUMAN sandbox profile only; no opaque-namespace conversion or provider delegation claim. */
public final class SandboxPolicyBindingAdmissionImpl implements PolicyBindingAdmission,AuditAppendAuthority {
    public record Profile(String issuer,String audience,String allowedClientId,String platformTenant,UUID resourceTenantId,
            UUID configurationBindingId,long configurationBindingVersion,String configurationBindingDigest) {
        public Profile {
            PolicyBindingValues.text(issuer,512);PolicyBindingValues.text(audience,255);PolicyBindingValues.text(allowedClientId,255);
            PolicyBindingValues.text(platformTenant,255);PolicyBindingValues.id(resourceTenantId);PolicyBindingValues.id(configurationBindingId);
            PolicyBindingValues.digest(configurationBindingDigest);
            if(configurationBindingVersion<1 || !platformTenant.equals(resourceTenantId.toString()))throw denied();
        }
    }
    private final SecurityContextPort security;
    private final PolicyEvaluationPort pdp;
    private final Profile profile;
    private final Clock clock;
    private final java.util.function.LongSupplier nanos;
    private final Supplier<UUID> ids;
    private final Object executionKey=new Object(),appendKey=new Object();
    public SandboxPolicyBindingAdmissionImpl(SecurityContextPort security,PolicyEvaluationPort pdp,Profile profile,Clock clock,
            java.util.function.LongSupplier nanos,Supplier<UUID> ids){this.security=Objects.requireNonNull(security);this.pdp=Objects.requireNonNull(pdp);
        this.profile=Objects.requireNonNull(profile);this.clock=Objects.requireNonNull(clock);this.nanos=Objects.requireNonNull(nanos);this.ids=Objects.requireNonNull(ids);}
    public GovernedPolicyService scoped(GovernedPolicyService delegate){return new GovernedPolicyService(){
        public Mono<GovernedPolicyCommandResponse> bind(GovernedPolicyBindRequest r){return writeInvoke(Request.bind(r),()->delegate.bind(r));}
        public Mono<GovernedPolicyCommandResponse> issue(UUID policyId,GovernedPolicyIssueRequest r){return writeInvoke(new Request(Action.ISSUE,r.actionId(),r.intentDigest(policyId),policyId,null,null,null,null),()->delegate.issue(policyId,r));}
        public Mono<GovernedPolicyRecoveryResponse> recover(UUID actionId,String digest){return invoke(new Request(Action.RECOVER,actionId,digest,null,null,null,null,null),()->delegate.recover(actionId,digest)).onErrorMap(error->new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_GATEWAY,"Protected policy recovery unavailable"));}
    };}
    private Mono<GovernedPolicyCommandResponse> writeInvoke(Request request,Supplier<Mono<GovernedPolicyCommandResponse>> work){
        return invoke(request,work)
            .onErrorResume(ProjectionExpiredExceptionImpl.class,error->Mono.just(new GovernedPolicyCommandResponse(error.status,request.actionId(),request.intentDigest(),null)))
            .onErrorResume(PolicyBindingRefusedException.class,error->Mono.just(new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.REFUSED,request.actionId(),request.intentDigest(),null)))
            .onErrorResume(java.util.concurrent.TimeoutException.class,error->Mono.just(new GovernedPolicyCommandResponse(GovernedPolicyCommandResponse.Status.OUTCOME_UNKNOWN,request.actionId(),request.intentDigest(),null)));
    }
    private <T> Mono<T> invoke(Request request,Supplier<Mono<T>> work){return Mono.deferContextual(context->{
        if(context.hasKey(executionKey))return Mono.error(denied());Instant observed=clock.instant();long before=nanos.getAsLong();
        return security.currentPrincipal().switchIfEmpty(Mono.error(denied())).onErrorMap(error->denied()).flatMap(principal->{
            requirePrincipal(principal,request);Instant expiry=principal.claim("exp",Instant.class);Instant until=expiry.isBefore(observed.plusSeconds(5))?expiry:observed.plusSeconds(5);
            var execution=new ExecutionImpl(request,principal,observed,before,until,PolicyBindingValues.id(ids.get()),PolicyBindingValues.id(ids.get()));
            return Mono.using(()->execution,held->Mono.defer(work).timeout(remaining(held)).contextWrite(current->current.put(executionKey,held)),held->held.active.set(false),true).map(value->{
                try{window(execution);}catch(PolicyBindingRefusedException expired){throw new ProjectionExpiredExceptionImpl(value);}
                return value;
            });
        }).timeout(Duration.between(observed,observed.plusSeconds(5)));
    });}
    @Override public Mono<PolicyBindingAdmission.Permit> requireCurrent(Request request){return Mono.deferContextual(context->{
        ExecutionImpl execution=current(context);if(!execution.request.equals(request) || execution.permit.get()!=null)return Mono.error(denied());
        return evaluation(execution,"authorize").map(value->{
            var provenance=value.provenance().orElseThrow();execution.authorization=value;
            var actor=new AuditActor(execution.principal.issuer(),execution.principal.subject(),profile.allowedClientId(),execution.principal.tenantId(),null,null);
            var permit=new PolicyBindingAdmission.Permit(request,profile.resourceTenantId(),UUID.fromString(execution.principal.claim("party_id",String.class)),profile.configurationBindingId(),profile.configurationBindingVersion(),profile.configurationBindingDigest(),actor,
                provenance.policyRevision(),execution.processId,execution.correlationId,execution.observedAt,execution.observedNanos,execution.until);
            if(!execution.permit.compareAndSet(null,permit))throw denied();return permit;
        });
    });}
    @Override public Mono<Void> revalidate(PolicyBindingAdmission.Permit permit){return Mono.deferContextual(context->{
        ExecutionImpl execution=current(context);if(execution.permit.get()!=permit)return Mono.error(denied());
        if(execution.admission!=null && !execution.appended.get())return principal(execution).then();
        return evaluation(execution,execution.appended.get()?"response":"admit").doOnNext(value->{
            if(!execution.appended.get()){
                execution.admission=value;
            }
        }).then();
    });}
    @Override public Mono<PolicyBindingDecisionEvidence> requireDecisionEvidence(PolicyBindingAdmission.Permit permit){return Mono.deferContextual(context->{
        ExecutionImpl execution=current(context);if(execution.permit.get()!=permit || execution.authorization==null || execution.admission==null || !execution.captured.compareAndSet(false,true))return Mono.error(denied());
        return Mono.just(new PolicyBindingDecisionEvidence(execution.authorization.provenance().orElseThrow(),execution.admission.provenance().orElseThrow()));
    });}
    @Override public <T> Mono<T> withinExpectedAppend(PolicyBindingAdmission.Permit permit,AuditEvent event,Supplier<Mono<T>> work){return Mono.deferContextual(context->{
        ExecutionImpl execution=current(context);if(execution.permit.get()!=permit || !execution.captured.get() || context.hasKey(appendKey)
                || !permit.actor().equals(event.actor()) || !permit.resourceTenantId().equals(event.stream().resourceTenantId())
                || !execution.admission.provenance().orElseThrow().policyRevision().equals(event.policyRevision()) || !execution.appended.compareAndSet(false,true))return Mono.error(denied());
        var expected=new ExpectedImpl(execution,event);return Mono.defer(work).contextWrite(current->current.put(appendKey,expected));
    });}
    @Override public Mono<AuditAppendAuthority.Permit> requireCurrent(AuditEvent event){return Mono.deferContextual(context->{
        ExecutionImpl execution=current(context);Object value=context.getOrDefault(appendKey,null);
        if(!(value instanceof ExpectedImpl expected) || expected.execution!=execution || !expected.event.equals(event) || expected.calls.incrementAndGet()>2)return Mono.error(denied());
        return principal(execution).map(ignored->new AuditAppendAuthority.Permit(event.stream(),execution.permit.get().actor(),execution.until));
    });}
    private Mono<PolicyEvaluation> evaluation(ExecutionImpl execution,String role){return principal(execution).flatMap(principal->{
        Map<String,Object> facts=new LinkedHashMap<>();facts.put("profile","insurance-policy-human-uuid-sandbox-1");facts.put("role",role);
        facts.put("resourceTenantId",profile.resourceTenantId());facts.put("configurationBindingId",profile.configurationBindingId());
        facts.put("configurationBindingVersion",profile.configurationBindingVersion());facts.put("configurationBindingDigest",profile.configurationBindingDigest());
        facts.put("partyId",UUID.fromString(execution.principal.claim("party_id",String.class)));facts.put("actionId",execution.request.actionId());facts.put("intentDigest",execution.request.intentDigest());
        if(execution.request.policyId()!=null)facts.put("policyId",execution.request.policyId());
        if(execution.request.submissionId()!=null){facts.put("submissionId",execution.request.submissionId());facts.put("partyId",execution.request.partyId());facts.put("productId",execution.request.productId());
            var intent=execution.request.bindingIntent();facts.put("contractId",intent.contractId());facts.put("offerId",intent.offerId());facts.put("offerVersion",intent.offerVersion());
            facts.put("acceptedControlGeneration",intent.acceptedControlGeneration());facts.put("acceptanceActionId",intent.acceptanceActionId());
            facts.put("acceptanceIntentDigest",intent.acceptanceIntentDigest());facts.put("termsDigest",intent.termsDigest());
            facts.put("coverageStart",intent.inceptionDate().toString());facts.put("coverageEnd",intent.expiryDate().toString());
            facts.put("policyNumberDigest",PolicyBindingValues.hash("CORE_POLICY_NUMBER_V1",intent.policyNumber()));}
        return pdp.evaluate(principal,"insurance.policy."+execution.request.action().name().toLowerCase(Locale.ROOT)+"."+role,
                "urn:firefly:insurance:policy:tenant:"+profile.resourceTenantId()+":action:"+execution.request.actionId(),Map.copyOf(facts))
            .switchIfEmpty(Mono.error(denied())).flatMap(value->{
                if(!value.decision().granted() || !value.decision().obligations().isEmpty() || value.provenance().isEmpty())return Mono.error(denied());
                return principal(execution).thenReturn(value);
            });
    }).timeout(remaining(execution)).onErrorMap(error->denied());}
    private Mono<SecurityPrincipal> principal(ExecutionImpl execution){return Mono.defer(security::currentPrincipal).filter(execution.principal::equals)
        .switchIfEmpty(Mono.error(denied())).map(value->{requirePrincipal(value,execution.request);remaining(execution);return value;}).onErrorMap(error->denied());}
    private void requirePrincipal(SecurityPrincipal value,Request request){Instant now=clock.instant();Instant exp=value.claim("exp",Instant.class),nbf=value.claim("nbf",Instant.class);
        List<?> audiences=value.claim("aud",List.class);String party=value.claim("party_id",String.class);
        if(!profile.issuer().equals(value.issuer()) || value.subject()==null || value.subject().isBlank() || !profile.platformTenant().equals(value.tenantId())
            || !profile.allowedClientId().equals(value.claim("client_id",String.class)) || !"HUMAN".equals(value.claim("principal_kind",String.class))
            || audiences==null || audiences.size()!=1 || !profile.audience().equals(audiences.getFirst()) || exp==null || nbf==null || !now.isBefore(exp) || now.isBefore(nbf)
            || party==null || !party.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            || request.partyId()!=null&&!request.partyId().toString().equals(party)
            || !value.hasScope("insurance:policies:"+request.action().name().toLowerCase(Locale.ROOT))
            || request.action()==Action.RECOVER&&!value.hasScope("insurance:policies:read"))throw denied();
    }
    private ExecutionImpl current(reactor.util.context.ContextView context){Object value=context.getOrDefault(executionKey,null);if(!(value instanceof ExecutionImpl execution) || !execution.active.get())throw denied();remaining(execution);return execution;}
    private Duration remaining(ExecutionImpl execution){if(!execution.active.get())throw denied();return window(execution);}
    private Duration window(ExecutionImpl execution){long elapsed=nanos.getAsLong()-execution.observedNanos;
        var wall=Duration.between(clock.instant(),execution.until);var monotonic=Duration.between(execution.observedAt,execution.until).minusNanos(elapsed);
        if(elapsed<0 || wall.isNegative() || wall.isZero() || monotonic.isNegative() || monotonic.isZero())throw denied();return wall.compareTo(monotonic)<0?wall:monotonic;}
    private static final class ProjectionExpiredExceptionImpl extends IllegalStateException {
        @java.io.Serial private static final long serialVersionUID=1L;
        final GovernedPolicyCommandResponse.Status status;
        ProjectionExpiredExceptionImpl(Object value){super("Original policy projection window ended");
            status=value instanceof GovernedPolicyCommandResponse command && (command.status()==GovernedPolicyCommandResponse.Status.COMMITTED || command.status()==GovernedPolicyCommandResponse.Status.COMMITTED_RESPONSE_UNAVAILABLE)
                ?GovernedPolicyCommandResponse.Status.COMMITTED_RESPONSE_UNAVAILABLE:GovernedPolicyCommandResponse.Status.OUTCOME_UNKNOWN;}
    }
    private static final class ExecutionImpl {
        final Request request;final SecurityPrincipal principal;final Instant observedAt,until;final long observedNanos;final UUID processId,correlationId;
        final AtomicBoolean active=new AtomicBoolean(true),appended=new AtomicBoolean(),captured=new AtomicBoolean();
        final AtomicReference<PolicyBindingAdmission.Permit> permit=new AtomicReference<>();PolicyEvaluation authorization,admission;
        ExecutionImpl(Request request,SecurityPrincipal principal,Instant observedAt,long observedNanos,Instant until,UUID processId,UUID correlationId){this.request=request;this.principal=principal;this.observedAt=observedAt;this.observedNanos=observedNanos;this.until=until;this.processId=processId;this.correlationId=correlationId;}
    }
    private static final class ExpectedImpl {final ExecutionImpl execution;final AuditEvent event;final AtomicInteger calls=new AtomicInteger();ExpectedImpl(ExecutionImpl execution,AuditEvent event){this.execution=execution;this.event=event;}}
    private static PolicyBindingRefusedException denied(){return new PolicyBindingRefusedException();}
    @Override public String toString(){return "SandboxPolicyBindingAdmissionImpl[redacted]";}
}
