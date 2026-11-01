package io.fireflysoftware.core.insurance.policies.core.services.binding.fixture;

import io.fireflysoftware.core.insurance.policies.interfaces.enums.*;
import io.fireflysoftware.core.insurance.policies.models.config.R2dbcConfiguration;
import io.fireflysoftware.core.insurance.policies.models.entities.*;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.r2dbc.postgresql.api.*;
import io.r2dbc.postgresql.codec.*;
import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import java.time.Duration;
import java.util.*;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Test;
import org.springframework.data.r2dbc.core.DefaultReactiveDataAccessStrategy;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Update;
import org.springframework.r2dbc.core.binding.BindTarget;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Actual owner converters and driver registrar over controlled type metadata; native acceptance stays separate. */
class NativePolicyEnumMappingTest {
    @Test void ownerMappingKeepsOnlyTheTwoRegisteredCasEnumsNative() {
        var strategy=new DefaultReactiveDataAccessStrategy(PostgresDialect.INSTANCE,R2dbcConfiguration.policyEnumConverters());
        var policy=strategy.getOutboundRow(Policy.builder().policyStatus(PolicyStatus.BOUND).lineOfBusiness(LineOfBusiness.PROPERTY).build());
        assertSame(PolicyStatus.BOUND,policy.get(strategy.getMappingContext().getRequiredPersistentEntity(Policy.class).getRequiredPersistentProperty("policyStatus").getColumnName()).getValue());
        assertSame(LineOfBusiness.PROPERTY,policy.get(strategy.getMappingContext().getRequiredPersistentEntity(Policy.class).getRequiredPersistentProperty("lineOfBusiness").getColumnName()).getValue());
        assertEquals("POLICYHOLDER",strategy.getOutboundRow(PolicyParty.builder().role(PolicyPartyRole.POLICYHOLDER).build()).get(strategy.getMappingContext().getRequiredPersistentEntity(PolicyParty.class).getRequiredPersistentProperty("role").getColumnName()).getValue());
        assertEquals("NEW_BUSINESS",strategy.getOutboundRow(PolicyTransaction.builder().transactionType(PolicyTransactionType.NEW_BUSINESS).build()).get(strategy.getMappingContext().getRequiredPersistentEntity(PolicyTransaction.class).getRequiredPersistentProperty("transactionType").getColumnName()).getValue());
        var mapper=strategy.getStatementMapper().forType(Policy.class);
        var cas=Criteria.where("policyStatus").is(PolicyStatus.BOUND).and("lineOfBusiness").is(LineOfBusiness.PROPERTY);
        var operation=mapper.getMappedObject(mapper.createUpdate(strategy.getTableName(Policy.class),Update.update("policyStatus",PolicyStatus.IN_FORCE)).withCriteria(cas));
        var bindings=new ArrayList<Object>();BindTarget target=mock(BindTarget.class);
        doAnswer(call->{bindings.add(call.getArgument(1));return null;}).when(target).bind(anyInt(),any());operation.bindTo(target);
        assertEquals(3,bindings.size());assertTrue(bindings.containsAll(List.of(PolicyStatus.IN_FORCE,PolicyStatus.BOUND,LineOfBusiness.PROPERTY)));assertTrue(bindings.stream().allMatch(Enum.class::isInstance));
        var connection=mock(PostgresqlConnection.class);var statement=mock(PostgresqlStatement.class);var result=mock(PostgresqlResult.class);var metadata=mock(RowMetadata.class);
        var status=mock(Row.class);when(status.get("oid",Long.class)).thenReturn(19001L);when(status.get("typname",String.class)).thenReturn("policy_status_enum");when(status.get("typcategory",String.class)).thenReturn("E");
        var line=mock(Row.class);when(line.get("oid",Long.class)).thenReturn(19002L);when(line.get("typname",String.class)).thenReturn("line_of_business_enum");when(line.get("typcategory",String.class)).thenReturn("E");
        when(connection.createStatement(anyString())).thenReturn(statement);doReturn(Flux.just(result)).when(statement).execute();
        doAnswer(call->{BiFunction<Row,RowMetadata,Object> mapping=call.getArgument(0);return Flux.just(status,line).map(row->mapping.apply(row,metadata));}).when(result).map(any(BiFunction.class));
        var registered=new ArrayList<Codec<?>>();var registry=mock(CodecRegistry.class);
        doAnswer(call->{registered.add(call.getArgument(0));return null;}).when(registry).addLast(any(Codec.class));
        Mono.from(R2dbcConfiguration.policyEnumCodecs().register(connection,UnpooledByteBufAllocator.DEFAULT,registry)).block(Duration.ofSeconds(2));
        assertEquals(2,registered.size());assertEquals(1,registered.stream().filter(codec->codec.canEncode(PolicyStatus.BOUND) && codec.canEncode(PolicyStatus.IN_FORCE)).count());assertEquals(1,registered.stream().filter(codec->codec.canEncode(LineOfBusiness.PROPERTY)).count());
        for(var codec:registered){assertFalse(codec.canEncode(PolicyPartyRole.POLICYHOLDER));assertFalse(codec.canEncode(PolicyTransactionType.NEW_BUSINESS));}
        verify(connection).createStatement(argThat(sql->sql.contains("'policy_status_enum'") && sql.contains("'line_of_business_enum'") && !sql.contains("policy_party_role_enum") && !sql.contains("policy_transaction_type_enum")));
    }
}
