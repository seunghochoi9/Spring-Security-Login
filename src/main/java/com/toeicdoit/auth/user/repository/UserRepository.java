package com.toeicdoit.auth.user.repository;

import com.toeicdoit.auth.user.entity.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<UserModel, Long> {

    Boolean existsByUsername(String username);

    UserModel findByUsername(String username);
}
