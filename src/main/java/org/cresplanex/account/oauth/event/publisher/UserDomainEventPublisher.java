package org.cresplanex.account.oauth.event.publisher;

import org.cresplanex.account.oauth.entity.UserEntity;
import org.cresplanex.api.state.common.event.EventAggregateType;
import org.cresplanex.api.state.common.event.model.user.UserDomainEvent;
import org.cresplanex.api.state.common.event.publisher.AggregateDomainEventPublisher;
import org.cresplanex.core.events.publisher.DomainEventPublisher;
import org.springframework.stereotype.Component;

@Component
public class UserDomainEventPublisher extends AggregateDomainEventPublisher<UserEntity, UserDomainEvent> {

    public UserDomainEventPublisher(DomainEventPublisher eventPublisher) {
        super(eventPublisher, UserEntity.class, EventAggregateType.USER);
    }
}
