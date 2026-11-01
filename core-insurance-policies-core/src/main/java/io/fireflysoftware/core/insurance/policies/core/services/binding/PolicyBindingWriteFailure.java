/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

import io.fireflysoftware.core.insurance.policies.interfaces.binding.GovernedPolicyCommandResponse;
public final class PolicyBindingWriteFailure extends IllegalStateException {
    @java.io.Serial private static final long serialVersionUID=1L;
    private final GovernedPolicyCommandResponse.Status status;
    public PolicyBindingWriteFailure(GovernedPolicyCommandResponse.Status status){super("Governed policy transaction completion requires recovery");this.status=status;}
    public GovernedPolicyCommandResponse.Status status(){return status;}
}
