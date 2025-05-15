package ru.stitchonfire.sso.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.stitchonfire.sso.security.model.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

}
