/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Objects;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record GovernedPolicyCommandResponse(@Schema(requiredMode=Schema.RequiredMode.REQUIRED) Status status,
        @Schema(requiredMode=Schema.RequiredMode.REQUIRED) UUID actionId,
        @Schema(requiredMode=Schema.RequiredMode.REQUIRED) String intentDigest,
        @Schema(nullable=true) GovernedPolicyBindingResult result) {
    public enum Status {COMMITTED,COMMITTED_RESPONSE_UNAVAILABLE,OUTCOME_UNKNOWN,REFUSED}
    public GovernedPolicyCommandResponse {Objects.requireNonNull(status);PolicyBindingValues.id(actionId);PolicyBindingValues.digest(intentDigest);
        if((status==Status.COMMITTED)!=(result!=null))throw new IllegalArgumentException("Exact policy command completion required");}
    @Override public String toString(){return "GovernedPolicyCommandResponse["+status+"]";}
}
