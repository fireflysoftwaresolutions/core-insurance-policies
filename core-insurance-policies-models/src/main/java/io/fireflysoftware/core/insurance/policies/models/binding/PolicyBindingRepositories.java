/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.core.insurance.policies.models.binding;

import java.util.UUID;
import org.springframework.data.repository.Repository;
import reactor.core.publisher.Mono;
public final class PolicyBindingRepositories {
    private PolicyBindingRepositories(){}
    public interface Operations extends Repository<PolicyBindingOperation,UUID> {
        Mono<PolicyBindingOperation> findByTenantIdAndOwnerIssuerAndOwnerSubjectAndActionId(UUID tenantId,String ownerIssuer,String ownerSubject,UUID actionId);
    }
    public interface Bindings extends Repository<PolicyBindingSnapshot,UUID> {
        Mono<PolicyBindingSnapshot> findByTenantIdAndOwnerIssuerAndOwnerSubjectAndPolicyId(UUID tenantId,String ownerIssuer,String ownerSubject,UUID policyId);
    }
    public interface Receipts extends Repository<PolicyBindingReceipt,UUID> {
        Mono<PolicyBindingReceipt> findByReceiptIdAndTenantIdAndOwnerIssuerAndOwnerSubject(UUID receiptId,UUID tenantId,String ownerIssuer,String ownerSubject);
    }
}
