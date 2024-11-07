package org.cresplanex.account.oauth.event.model.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserCreated implements UserDomainEvent {

    private String userId;
    private String name;
    private String email;
    private String nickname;
}
