package org.cresplanex.account.oauth.auth;

import lombok.RequiredArgsConstructor;
import org.cresplanex.account.oauth.entity.AccountEntity;
import org.cresplanex.account.oauth.repository.AccountRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AccountDetailsService implements UserDetailsService {

    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AccountEntity account = accountRepository.findByLoginId(username).orElseThrow(() -> new
                UsernameNotFoundException("User details not found for the user: " + username));
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.getRole()));
//        List<GrantedAuthority> authorities = account.getAuthorities().stream().map(authority -> new
//                SimpleGrantedAuthority(authority.getName())).collect(Collectors.toList());
        return new User(account.getLoginId(), account.getPasswordHash(), authorities);
    }
}
