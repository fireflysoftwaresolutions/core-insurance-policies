/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.*;
import java.util.UUID;
import reactor.core.publisher.Mono;
public interface GovernedPolicyService {
    Mono<GovernedPolicyCommandResponse> bind(GovernedPolicyBindRequest request);
    Mono<GovernedPolicyCommandResponse> issue(UUID policyId,GovernedPolicyIssueRequest request);
    Mono<GovernedPolicyRecoveryResponse> recover(UUID actionId,String intentDigest);
}
