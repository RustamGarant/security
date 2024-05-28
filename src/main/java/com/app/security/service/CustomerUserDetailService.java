package com.app.security.service;

import com.app.security.entity.*;
import com.app.security.repository.*;
import lombok.*;
import org.springframework.security.core.authority.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.*;

@Service
@RequiredArgsConstructor
public class CustomerUserDetailService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        customerRepository.findByUsername(username)
            .map(user -> User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities().stream()
                    .map(Authority::getAuthority)
                    .map(SimpleGrantedAuthority::new)
                    .toList())
                .build())
            .orElseThrow(() -> new UsernameNotFoundException(String.format("User %s not found", username)));

        return null;
    }
}
