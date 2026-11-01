/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.models.binding;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;
import reactor.core.publisher.Mono;

/** Narrow technical integrity guards; owner installation is explicit and never performed here. */
public interface PolicyBindingNativeIntegrity extends Repository<PolicyBindingOperation,UUID> {
    @Query("SELECT insurance_policy_binding_private.verify_protocol()") Mono<Boolean> verifyProtocol();
    @Query("SELECT insurance_policy_binding_private.verify_receipt(:operationId)") Mono<Boolean> verifyReceipt(@Param("operationId") UUID operationId);
}
