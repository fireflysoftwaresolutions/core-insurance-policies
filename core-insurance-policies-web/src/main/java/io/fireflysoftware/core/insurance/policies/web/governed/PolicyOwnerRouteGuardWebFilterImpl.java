package io.fireflysoftware.core.insurance.policies.web.governed;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Explicit owner-only mode closes every unsupported route, not just the governed controller. */
public final class PolicyOwnerRouteGuardWebFilterImpl implements WebFilter {
    static final ServerWebExchangeMatcher SUPPORTED=new OrServerWebExchangeMatcher(
            ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,"/api/v1/policies/governed/bindings","/api/v1/policies/*/governed/issue"),
            ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET,"/api/v1/policies/governed/recovery/*"));
    @Override public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain){
        return SUPPORTED.matches(exchange).flatMap(result->{
            if(result.isMatch())return chain.filter(exchange);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);return exchange.getResponse().setComplete();
        });
    }
}
