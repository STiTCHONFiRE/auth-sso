package ru.stitchonfire.sso.security.service;

import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.stitchonfire.sso.security.model.User;
import ru.stitchonfire.sso.security.repository.UserRepository;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CustomerUserDetailsService implements UserDetailsService {

    UserRepository userRepository;
    PasswordEncoder passwordEncoder;

    public CustomerUserDetailsService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.createUser();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public void createUser(String username, String password) {
        userRepository.save(
                User.builder()
                        .username(username)
                        .password(passwordEncoder.encode(password))
                        .build()
        );
    }

    public void createUser() {
        createUser("admin", "password");
        createUser("user", "password");
    }
}
