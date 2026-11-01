/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.interfaces.binding;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Objects;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record GovernedPolicyRecoveryResponse(@Schema(requiredMode=Schema.RequiredMode.REQUIRED) State state,
        @Schema(requiredMode=Schema.RequiredMode.REQUIRED) UUID actionId,
        @Schema(requiredMode=Schema.RequiredMode.REQUIRED) String intentDigest,
        @Schema(nullable=true) GovernedPolicyBindingResult result) {
    public enum State {FOUND,NOT_OBSERVED_AT_THIS_READ,INTENT_CONFLICT}
    public GovernedPolicyRecoveryResponse {Objects.requireNonNull(state);PolicyBindingValues.id(actionId);PolicyBindingValues.digest(intentDigest);
        if((state==State.FOUND)!=(result!=null))throw new IllegalArgumentException("Exact policy recovery observation required");}
    @Override public String toString(){return "GovernedPolicyRecoveryResponse["+state+"]";}
}
