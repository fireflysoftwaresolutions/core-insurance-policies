/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.core.services.binding;

public final class PolicyBindingRefusedException extends IllegalStateException {
    @java.io.Serial private static final long serialVersionUID=1L;
    public PolicyBindingRefusedException(){super("Governed policy intent or current authority refused");}
}
