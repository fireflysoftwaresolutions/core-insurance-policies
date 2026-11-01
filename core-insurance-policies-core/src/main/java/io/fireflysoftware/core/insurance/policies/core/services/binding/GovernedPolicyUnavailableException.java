/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
public final class GovernedPolicyUnavailableException extends ResponseStatusException {
    @java.io.Serial private static final long serialVersionUID=1L;
    public GovernedPolicyUnavailableException(){super(HttpStatus.SERVICE_UNAVAILABLE,"Trusted governed policy preparation unavailable");}
}
