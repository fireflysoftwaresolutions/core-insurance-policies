/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.underwriting.sdk.api.GovernedQuoteOffersApi;
import reactor.core.publisher.Mono;

/** Supplies a new caller-bound client only after supported, verified HUMAN subject-token exchange. */
public interface AcceptedQuoteClientProvider {
    Mono<GovernedQuoteOffersApi> requireExchangedClient(PolicyBindingAdmission.Permit original);
}
