/*
 * Copyright 2024-2026 Firefly Software Foundation
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
package io.fireflysoftware.core.insurance.policies.core.services.binding.fixture;

import io.r2dbc.spi.*;
import java.lang.reflect.Proxy;
import java.time.*;
import java.util.*;
import java.util.function.*;
import java.util.regex.*;
import org.fireflyframework.core.transaction.*;
import org.fireflyframework.core.transaction.impl.DefaultBoundedRootTransaction;
import org.reactivestreams.Publisher;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.r2dbc.connection.R2dbcTransactionManager;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import reactor.core.publisher.*;

/** Adapted from the original Jafly AuditTestFixture. Networkless mapping/count/transaction model, never PostgreSQL or authority qualification. Technical protocol acknowledgments are controlled inputs, not SQL execution. */
public final class PolicyBindingMappedFixture {
    Throwable workFailure;public final Clock clock;public final LongSupplier nanos;
    public PolicyBindingMappedFixture(){this(Clock.systemUTC(),System::nanoTime);}
    public PolicyBindingMappedFixture(Clock clock,LongSupplier nanos){this.clock=clock;this.nanos=nanos;}
    public final Driver driver=new Driver();final OwnedLeaseConnectionFactory factory=new OwnedLeaseConnectionFactory(driver);public final DatabaseClient client=DatabaseClient.create(factory);public final R2dbcEntityTemplate template=new R2dbcEntityTemplate(client,PostgresDialect.INSTANCE);public final R2dbcTransactionManager manager=new R2dbcTransactionManager(factory);public final BoundedR2dbcResources resources=BoundedR2dbcResources.verify(factory,client,template,manager);final BoundedRootTransaction root=new DefaultBoundedRootTransaction(resources,new CleanupPolicy(Duration.ofSeconds(1),Duration.ofSeconds(1)));
    <T> Mono<RootCompletion<T>> execute(Function<RootTransactionScope,Mono<T>> work){var now=clock.instant();return root.execute(R2dbcOperationBudget.observed(now,now.plusSeconds(5),nanos.getAsLong(),Duration.ofSeconds(5),clock,nanos),new DefaultTransactionDefinition(),scope->work.apply(scope).doOnError(error->workFailure=error));}
    public static final class Driver implements ConnectionFactory {
        public Map<String,List<Map<String,Object>>> tables=new HashMap<>(),snapshot;Runnable beforeRead=()->{};Throwable readFailure;final List<String> sql=new ArrayList<>();final List<Map<Integer,Object>> bindings=new ArrayList<>();public int creates,writes,selects,affectedObservations,commits,rollbacks,closes,failWrite,nativeEnters,nativeCompletions,countAtWrite;public Mono<Void> commitGate=Mono.empty();public long writeCount=1;public boolean protocol=true,receiptGraph=true;public Runnable beforeMutation=()->{};boolean emptyCount;boolean autoCommit=true;
        Map<String,List<Map<String,Object>>> copy(){var out=new HashMap<String,List<Map<String,Object>>>();tables.forEach((t,rows)->out.put(t,new ArrayList<>(rows.stream().map(LinkedHashMap::new).toList())));return out;}
        final Connection connection=(Connection)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Connection.class},(p,m,a)->switch(m.getName()){
            case "isAutoCommit"->autoCommit;case "setAutoCommit"->{autoCommit=(boolean)a[0];yield Mono.empty();}case "getTransactionIsolationLevel"->IsolationLevel.READ_COMMITTED;
            case "beginTransaction"->Mono.fromRunnable(()->snapshot=copy());case "commitTransaction"->commitGate.then(Mono.fromRunnable(()->commits++));case "rollbackTransaction"->Mono.fromRunnable(()->{rollbacks++;tables=snapshot;});case "close"->Mono.fromRunnable(()->closes++);
            case "createStatement"->statement((String)a[0]);case "hashCode"->System.identityHashCode(p);case "equals"->p==a[0];case "toString"->"AuditNetworklessDriver";default->Mono.empty();});
        Statement statement(String originalQuery){sql.add(originalQuery);String query=originalQuery.replace("\"","");var bound=new LinkedHashMap<Integer,Object>();return (Statement)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Statement.class},(p,m,a)->{
            if(m.getName().equals("bind")||m.getName().equals("bindNull")){Object value=a[1];if(value instanceof Parameter parameter)value=parameter.getValue();bound.put((Integer)a[0],value instanceof Class?null:value);return p;}
            if(!m.getName().equals("execute"))return p;
            return Mono.defer(()->{
                bindings.add(new LinkedHashMap<>(bound));
                if(query.contains("insurance_policy_binding_private.verify_protocol"))return Mono.just(result(List.of(Map.of("verify_protocol",protocol)),0,false));
                if(query.contains("insurance_policy_binding_private.verify_receipt"))return Mono.just(result(List.of(Map.of("verify_receipt",receiptGraph)),0,false));
                if(query.contains("firefly_audit_enter")){nativeEnters++;return Mono.just(result(List.of(Map.of("context_nonce",bound.get(0),"event_id",bound.get(5),"db_now_millis",System.currentTimeMillis(),"until_millis",((java.time.OffsetDateTime)bound.get(12)).toInstant().toEpochMilli())),0,false));}
                if(query.contains("firefly_audit_complete")){nativeCompletions++;return Mono.just(result(List.of(Map.of("nonce",bound.get(0))),0,false));}
                String table=table(query);boolean mutation=query.startsWith("INSERT")||query.startsWith("UPDATE");
                if(mutation){beforeMutation.run();writes++;if(writes==failWrite)return Mono.error(new R2dbcDataIntegrityViolationException("ordinary duplicate"));long actualCount=countAtWrite==0||writes==countAtWrite?writeCount:1;if(actualCount==1){
                    if(query.startsWith("INSERT")){String text=query.substring(query.indexOf('(')+1,query.indexOf(')'));String[] columns=text.replace("\"","").split(",");var row=new LinkedHashMap<String,Object>();for(int i=0;i<columns.length;i++)row.put(columns[i].trim(),bound.get(i));tables.computeIfAbsent(table,k->new ArrayList<>()).add(row);}
                    else{var matching=new ArrayList<>(tables.getOrDefault(table,List.of()));var constraints=Pattern.compile("(?:[a-z_]+[.])?([a-z_]+) = [$]([0-9]+)").matcher(query.substring(query.indexOf(" WHERE ")+7));while(constraints.find()){String column=constraints.group(1);Object value=bound.get(Integer.parseInt(constraints.group(2))-1);matching.removeIf(row->!Objects.equals(row.get(column),value));}actualCount=matching.size();for(var row:matching){var matcher=Pattern.compile("([a-z_]+) = [$]([0-9]+)").matcher(query.substring(query.indexOf(" SET ")+5,query.indexOf(" WHERE ")));while(matcher.find())row.put(matcher.group(1),bound.get(Integer.parseInt(matcher.group(2))-1));}}
                }return Mono.just(result(List.of(),actualCount,true));}
                beforeRead.run();if(readFailure!=null&&query.contains("firefly_audit_require_completed"))return Mono.error(readFailure);
                selects++;var rows=new ArrayList<>(tables.getOrDefault(table,List.of()));var matches=Pattern.compile("(?:[a-z_]+[.])?([a-z_]+) = [$]([0-9]+)").matcher(query);while(matches.find()){String col=matches.group(1);Object v=bound.get(Integer.parseInt(matches.group(2))-1);rows.removeIf(row->!Objects.equals(row.get(col),v));}return Mono.just(result(rows,0,false));
            });
        });}
        String table(String query){var m=Pattern.compile("(?:INTO|UPDATE|FROM) (?:[a-z_]+[.])?([a-z_]+)").matcher(query.replace("\"",""));if(!m.find())throw new IllegalArgumentException(query);return m.group(1);}
        Result result(List<Map<String,Object>> values,long count,boolean mutation){return new Result(){
            public Publisher<Long> getRowsUpdated(){affectedObservations++;return emptyCount&&(countAtWrite==0||writes==countAtWrite)?Mono.empty():Mono.just(count);}
            public <T>Publisher<T> map(BiFunction<Row,RowMetadata,? extends T> f){return Flux.fromIterable(values).map(v->f.apply(row(v),metadata(v)));}
            public <T>Publisher<T> map(Function<? super io.r2dbc.spi.Readable,? extends T> f){return Flux.fromIterable(values).map(v->f.apply(row(v)));}
            public Result filter(Predicate<Segment> p){return this;}public <T>Publisher<T> flatMap(Function<Segment,? extends Publisher<? extends T>> f){return Flux.empty();}
        };}
        Row row(Map<String,Object> values){return (Row)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Row.class},(p,m,a)->{if(m.getName().equals("getMetadata"))return metadata(values);Object key=a[0]instanceof Integer i?new ArrayList<>(values.keySet()).get(i):a[0];return values.get(key);});}
        RowMetadata metadata(Map<String,Object> values){List<ColumnMetadata> columns=values.keySet().stream().map(n->(ColumnMetadata)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{ColumnMetadata.class},(p,m,a)->switch(m.getName()){case "getName"->n;case "getJavaType"->values.get(n)==null?String.class:values.get(n).getClass();case "getType"->new Type(){public Class<?> getJavaType(){return values.get(n)==null?String.class:values.get(n).getClass();}public String getName(){return "OrdinaryTypedColumn";}};default->null;})).toList();return (RowMetadata)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{RowMetadata.class},(p,m,a)->switch(m.getName()){case "getColumnMetadatas"->columns;case "getColumnMetadata"->a[0]instanceof Integer i?columns.get(i):columns.stream().filter(c->c.getName().equals(a[0])).findFirst().orElseThrow();case "contains"->values.containsKey(a[0]);default->null;});}
        public Publisher<? extends Connection> create(){creates++;return Mono.just(connection);}public ConnectionFactoryMetadata getMetadata(){return ()->"PostgreSQL";}
    }
}
