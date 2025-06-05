package ru.stitchonfire.sso.security.service;

import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import ru.stitchonfire.sso.security.repository.UserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class OidcUserInfoService {

    UserInfoRepository userInfoRepository;

    @Autowired
    public OidcUserInfoService(UserRepository userRepository) {
        this.userInfoRepository = new UserInfoRepository(userRepository);
    }

    public OidcUserInfo loadUser(String username) {
        return new OidcUserInfo(this.userInfoRepository.findByUsername(username));
    }

    public void createUser(String username) {
        this.userInfoRepository.userInfo.put(username, UserInfoRepository.createUser(username));
    }

    @FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
    static class UserInfoRepository {

        UserRepository userRepository;
        Map<String, Map<String, Object>> userInfo = new HashMap<>();

        public UserInfoRepository(UserRepository userRepository) {
            this.userRepository = userRepository;
        }

        @EventListener(ApplicationStartedEvent.class)
        public void loadInitialData() {
            this.userRepository.findAll().forEach(user -> {
                this.userInfo.put(user.getUsername(), createUser(user.getUsername()));
            });
        }

        public Map<String, Object> findByUsername(String username) {
            return this.userInfo.get(username);
        }

        private static Map<String, Object> createUser(String username) {
            return OidcUserInfo.builder()
                    .subject(username)
                    .name("First Last")
                    .givenName("First")
                    .familyName("Last")
                    .middleName("Middle")
                    .nickname("User")
                    .preferredUsername(username)
                    .profile("https://example.com/" + username)
                    .picture("https://example.com/" + username + ".jpg")
                    .website("https://example.com")
                    .email(username + "@example.com")
                    .emailVerified(true)
                    .gender("female")
                    .birthdate("1970-01-01")
                    .zoneinfo("Europe/Paris")
                    .locale("en-US")
                    .phoneNumber("+1 (604) 555-1234;ext=5678")
                    .phoneNumberVerified(false)
                    .claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
                    .updatedAt("1970-01-01T00:00:00Z")
                    .build()
                    .getClaims();
        }
    }

}
