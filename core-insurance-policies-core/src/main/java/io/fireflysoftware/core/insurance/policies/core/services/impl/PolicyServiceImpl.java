/*
 * Copyright 2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package io.fireflysoftware.core.insurance.policies.core.services.impl;

import org.fireflyframework.core.filters.FilterRequest;
import org.fireflyframework.core.filters.FilterUtils;
import org.fireflyframework.core.queries.PaginationResponse;
import org.fireflyframework.web.error.exceptions.ResourceNotFoundException;
import io.fireflysoftware.core.insurance.policies.core.mappers.PolicyMapper;
import io.fireflysoftware.core.insurance.policies.core.services.PolicyService;
import io.fireflysoftware.core.insurance.policies.interfaces.dtos.PolicyDTO;
import io.fireflysoftware.core.insurance.policies.interfaces.enums.PolicyStatus;
import io.fireflysoftware.core.insurance.policies.models.entities.Policy;
import io.fireflysoftware.core.insurance.policies.models.repositories.PolicyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
@Transactional
public class PolicyServiceImpl implements PolicyService {

    @Autowired
    private PolicyRepository repository;

    @Autowired
    private PolicyMapper mapper;

    @Override
    public Mono<PaginationResponse<PolicyDTO>> filterPolicies(FilterRequest<PolicyDTO> filterRequest) {
        return FilterUtils.createFilter(Policy.class, mapper::toDTO).filter(filterRequest);
    }

    @Override
    public Mono<PolicyDTO> createPolicy(PolicyDTO dto) {
        return Mono.just(dto)
                .map(mapper::toEntity)
                .doOnNext(entity -> {
                    if (entity.getPolicyStatus() == null) {
                        entity.setPolicyStatus(PolicyStatus.QUOTE);
                    }
                })
                .flatMap(repository::save)
                .map(mapper::toDTO);
    }

    @Override
    public Mono<PolicyDTO> updatePolicy(UUID policyId, PolicyDTO dto) {
        return repository.findById(policyId)
                .switchIfEmpty(Mono.error(ResourceNotFoundException.forResource("Policy", policyId.toString())))
                .flatMap(existing -> {
                    PolicyStatus current = existing.getPolicyStatus() != null
                            ? existing.getPolicyStatus()
                            : PolicyStatus.QUOTE;
                    mapper.updateEntityFromDto(dto, existing);
                    existing.setPolicyId(policyId);
                    PolicyStatus next = existing.getPolicyStatus() != null
                            ? existing.getPolicyStatus()
                            : current;
                    if (!PolicyLifecycleImpl.canTransition(current, next)) {
                        return Mono.error(new IllegalStateException(
                                "Policy " + policyId + " cannot move from " + current + " to " + next));
                    }
                    existing.setPolicyStatus(next);
                    return repository.save(existing);
                })
                .map(mapper::toDTO);
    }

    @Override
    public Mono<Void> deletePolicy(UUID policyId) {
        return repository.findById(policyId)
                .switchIfEmpty(Mono.error(ResourceNotFoundException.forResource("Policy", policyId.toString())))
                .flatMap(existing -> {
                    PolicyStatus status = existing.getPolicyStatus() != null
                            ? existing.getPolicyStatus()
                            : PolicyStatus.QUOTE;
                    if (status != PolicyStatus.QUOTE) {
                        return Mono.error(new IllegalStateException(
                                "Policy " + policyId + " is " + status
                                        + " and cannot be deleted; cancel or lapse it so the policy history is kept"));
                    }
                    return repository.deleteById(policyId);
                });
    }

    @Override
    public Mono<PolicyDTO> getPolicyById(UUID policyId) {
        return repository.findById(policyId)
                .switchIfEmpty(Mono.error(ResourceNotFoundException.forResource("Policy", policyId.toString())))
                .map(mapper::toDTO);
    }
}
