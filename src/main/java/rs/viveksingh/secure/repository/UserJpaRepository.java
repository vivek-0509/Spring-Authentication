package rs.viveksingh.secure.repository;

import rs.viveksingh.secure.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;

@Repository
public interface UserJpaRepository extends JpaRepository<User, Integer>
{

    //spring data jpa automatically implements this method
    User findByUsername(String username);

}

