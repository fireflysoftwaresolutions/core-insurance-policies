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

import io.fireflysoftware.core.insurance.policies.interfaces.enums.PolicyStatus;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Allowed moves for a policy. A quote is the only status that can be removed.
 */
final class PolicyLifecycleImpl {

    private static final Map<PolicyStatus, Set<PolicyStatus>> ALLOWED = Map.of(
            PolicyStatus.QUOTE, EnumSet.of(PolicyStatus.BOUND, PolicyStatus.CANCELLED),
            PolicyStatus.BOUND, EnumSet.of(PolicyStatus.IN_FORCE, PolicyStatus.CANCELLED),
            PolicyStatus.IN_FORCE, EnumSet.of(PolicyStatus.LAPSED, PolicyStatus.CANCELLED, PolicyStatus.EXPIRED),
            PolicyStatus.LAPSED, EnumSet.of(PolicyStatus.IN_FORCE, PolicyStatus.CANCELLED, PolicyStatus.EXPIRED)
    );

    private PolicyLifecycleImpl() {
    }

    static boolean canTransition(PolicyStatus from, PolicyStatus to) {
        if (from == to) {
            return true;
        }
        Set<PolicyStatus> next = ALLOWED.get(from);
        return next != null && next.contains(to);
    }
}
