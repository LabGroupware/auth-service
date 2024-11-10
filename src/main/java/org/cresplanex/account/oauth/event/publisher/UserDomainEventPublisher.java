package org.cresplanex.account.oauth.event.publisher;

import org.cresplanex.account.oauth.event.EventAggregateChannel;
import org.cresplanex.account.oauth.entity.UserEntity;
import org.cresplanex.account.oauth.event.model.user.UserDomainEvent;
import org.cresplanex.core.events.aggregates.AbstractAggregateDomainEventPublisher;
import org.cresplanex.core.events.publisher.DomainEventPublisher;
import org.springframework.stereotype.Component;

@Component
public class UserDomainEventPublisher extends AbstractAggregateDomainEventPublisher<UserEntity, UserDomainEvent> {

    public UserDomainEventPublisher(DomainEventPublisher eventPublisher) {
        super(eventPublisher, UserEntity.class, UserEntity::getUserId, EventAggregateChannel.USER);
    }
}
