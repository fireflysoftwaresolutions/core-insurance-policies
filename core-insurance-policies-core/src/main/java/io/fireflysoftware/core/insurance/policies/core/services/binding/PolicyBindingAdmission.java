/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.fireflyframework.kernel.audit.AuditActor;
import reactor.core.publisher.Mono;

/** Implementations must resolve the resource tenant through current authoritative server configuration. */
public interface PolicyBindingAdmission {
    enum Action {BIND,ISSUE,RECOVER}
    record Request(Action action,UUID actionId,String intentDigest,UUID policyId,UUID submissionId,UUID partyId,UUID productId,GovernedPolicyBindRequest bindingIntent) {
        public Request {Objects.requireNonNull(action);PolicyBindingValues.id(actionId);PolicyBindingValues.digest(intentDigest);
            if(action==Action.BIND){Objects.requireNonNull(bindingIntent);if(!actionId.equals(bindingIntent.actionId()) || !intentDigest.equals(bindingIntent.intentDigest()) || !Objects.equals(submissionId,bindingIntent.submissionId()) || !Objects.equals(partyId,bindingIntent.partyId()) || !Objects.equals(productId,bindingIntent.productId()))throw new IllegalArgumentException("Exact captured binding intent required");PolicyBindingValues.id(submissionId);PolicyBindingValues.id(partyId);PolicyBindingValues.id(productId);if(policyId!=null)throw new IllegalArgumentException("New binding must not select a policy");}
            else {if(bindingIntent!=null)throw new IllegalArgumentException("Unexpected binding intent");if(action==Action.ISSUE)PolicyBindingValues.id(policyId);}}
        public static Request bind(GovernedPolicyBindRequest value){return new Request(Action.BIND,value.actionId(),value.intentDigest(),null,value.submissionId(),value.partyId(),value.productId(),value);}
        @Override public String toString(){return "PolicyBindingAdmissionRequest["+action+"]";}
    }
    record Permit(Request request,UUID resourceTenantId,UUID partyId,UUID bindingId,long bindingVersion,String bindingDigest,AuditActor actor,
            String authorizationPolicyRevision,UUID processId,UUID correlationId,Instant observedAt,long observedNanos,Instant notAfter) {
        public Permit {Objects.requireNonNull(request);PolicyBindingValues.id(resourceTenantId);PolicyBindingValues.id(partyId);PolicyBindingValues.id(bindingId);PolicyBindingValues.digest(bindingDigest);
            Objects.requireNonNull(actor);PolicyBindingValues.text(authorizationPolicyRevision,128);PolicyBindingValues.id(processId);
            PolicyBindingValues.id(correlationId);Objects.requireNonNull(observedAt);Objects.requireNonNull(notAfter);if(bindingVersion<1 || !notAfter.isAfter(observedAt) || java.time.Duration.between(observedAt,notAfter).compareTo(java.time.Duration.ofSeconds(5))>0)throw new IllegalArgumentException("Trusted policy binding required");}
        public java.time.Duration remaining(java.time.Clock clock,java.util.function.LongSupplier nanos){
            var wall=java.time.Duration.between(clock.instant(),notAfter);long elapsed=nanos.getAsLong()-observedNanos;
            var monotonic=java.time.Duration.between(observedAt,notAfter).minusNanos(elapsed);
            if(elapsed<0 || wall.isZero() || wall.isNegative() || monotonic.isZero() || monotonic.isNegative())throw new PolicyBindingRefusedException();
            return wall.compareTo(monotonic)<0?wall:monotonic;
        }
        @Override public String toString(){return "PolicyBindingPermit[redacted]";}
    }
    Mono<Permit> requireCurrent(Request request);
    Mono<Void> revalidate(Permit original);
    default Mono<PolicyBindingDecisionEvidence> requireDecisionEvidence(Permit original){return Mono.error(new GovernedPolicyUnavailableException());}
    default <T> Mono<T> withinExpectedAppend(Permit original,org.fireflyframework.kernel.audit.AuditEvent event,java.util.function.Supplier<Mono<T>> work){return Mono.defer(work);}
}
