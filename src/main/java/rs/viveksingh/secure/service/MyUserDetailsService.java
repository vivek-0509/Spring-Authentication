package rs.viveksingh.secure.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import rs.viveksingh.secure.model.UserPrinciple;
import rs.viveksingh.secure.model.User;
import rs.viveksingh.secure.repository.UserJpaRepository;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private UserJpaRepository repo;

    public MyUserDetailsService(UserJpaRepository repo) {
        this.repo = repo;
    }


    //UserDetails is a interface
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user =repo.findByUsername(username);

        if(user == null) {
            System.out.println("user not found");
            throw new UsernameNotFoundException("User not found");
        }


        return new UserPrinciple(user);
    }
}

