/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyBindRequest;
import reactor.core.publisher.Mono;
/** Adapter must use the actual generated Underwriting SDK and current protected acceptance/recovery reads. */
public interface AcceptedQuotePort {Mono<AcceptedQuoteEvidence> observe(PolicyBindingAdmission.Permit permit,GovernedPolicyBindRequest request);}
