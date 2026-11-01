/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest;
import reactor.core.publisher.Mono;
/** Requires an existing contract with the same trusted resource tenant, party, product and accepted currency. */
public interface PolicyContractPort {Mono<Void> requireExisting(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request,AcceptedQuoteEvidence quote);}
