package org.cresplanex.account.oauth.service;

import lombok.RequiredArgsConstructor;
import org.cresplanex.account.oauth.constants.EventTypes;
import org.cresplanex.account.oauth.constants.Role;
import org.cresplanex.account.oauth.entity.AccountEntity;
import org.cresplanex.account.oauth.event.model.user.UserCreated;
import org.cresplanex.account.oauth.event.publisher.UserDomainEventPublisher;
import org.cresplanex.account.oauth.exception.AccountDuplicateException;
import org.cresplanex.account.oauth.exception.UserDuplicateException;
import org.cresplanex.account.oauth.exception.UserNotFoundException;
import org.cresplanex.account.oauth.repository.AccountRepository;
import org.cresplanex.account.oauth.repository.UserRepository;
import org.cresplanex.account.oauth.entity.UserEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;

    private final UserDomainEventPublisher domainEventPublisher;

    public UserEntity create(AccountEntity account, String rawPassword, String name, String email)
            throws AccountDuplicateException, UserDuplicateException {
        account.setPasswordHash(passwordEncoder.encode(rawPassword));
        account.setRole(Role.USER);
        final String  loginId = account.getLoginId();
        accountRepository.findByLoginId(loginId).ifPresent(a -> {
            throw new AccountDuplicateException(
                    AccountDuplicateException.UniqueType.LOGIN_ID,
                    loginId
            );
        });
        account = accountRepository.save(account);

        userRepository.findByEmail(email).ifPresent(u -> {
            throw new UserDuplicateException(
                    UserDuplicateException.UniqueType.EMAIL,
                    email
            );
        });
        UserEntity user = new UserEntity();
        user.setAccount(account);
        user.setName(name);
        user.setPreferredUsername(name);
        user.setNickname(name);
        user.setEmail(email);
        user = userRepository.save(user);

        domainEventPublisher.publish(user, Collections.singletonList(new UserCreated(
                        user.getUserId(),
                        user.getName(),
                        user.getEmail(),
                        user.getNickname()
                        )),
                EventTypes.USER_CREATED);

        return user;
    }

    public UserEntity findByEmail(String email)
    throws UserNotFoundException {
        Optional<UserEntity> userEntity = userRepository.findByEmail(email);

        if (userEntity.isEmpty()) {
            throw new UserNotFoundException(
                UserNotFoundException.FindType.EMAIL,
                email
            );
        }

        return userEntity.get();
    }

    public UserEntity findById(String userId)
        throws UserNotFoundException {
        Optional<UserEntity> userEntity = userRepository.findById(userId);

        if (userEntity.isEmpty()) {
            throw new UserNotFoundException(
                UserNotFoundException.FindType.USER_ID,
                userId
            );
        }

        return userEntity.get();
    }

    public List<UserEntity> getList() {
        return userRepository.findAll();
    }
}
