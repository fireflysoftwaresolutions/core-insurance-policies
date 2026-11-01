/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.PolicyBindingValues;
import java.util.Objects;
import org.fireflyframework.security.api.domain.PolicyEvaluationProvenance;

/** Actual same-response provenance retained for both evaluation roles, never synthesized from context or a hash. */
public record PolicyBindingDecisionEvidence(PolicyEvaluationProvenance authorization,PolicyEvaluationProvenance admission) {
    public PolicyBindingDecisionEvidence {Objects.requireNonNull(authorization);Objects.requireNonNull(admission);
        for(var value:java.util.List.of(authorization,admission)){PolicyBindingValues.text(value.policyRevision(),128);PolicyBindingValues.text(value.decisionId(),1024);}}
    public String digest(){return PolicyBindingValues.hash("CORE_POLICY_DECISIONS_V1",authorization.policyRevision(),authorization.decisionId(),admission.policyRevision(),admission.decisionId());}
    @Override public String toString(){return "PolicyBindingDecisionEvidence[redacted]";}
}
