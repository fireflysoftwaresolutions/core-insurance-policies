/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.util.UUID;
import reactor.core.publisher.Mono;
/** Only the Core owned root may produce committed receipts; an implementation has no permissive fallback. */
public interface PolicyBindingStore {
    Mono<GovernedPolicyCommandResponse> bind(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request,AcceptedQuoteEvidence quote);
    Mono<GovernedPolicyCommandResponse> issue(PolicyBindingAdmission.Permit permit,UUID policyId,GovernedPolicyIssueRequest request);
    Mono<GovernedPolicyRecoveryResponse> recover(PolicyBindingAdmission.Permit permit,UUID actionId,String intentDigest);
}
