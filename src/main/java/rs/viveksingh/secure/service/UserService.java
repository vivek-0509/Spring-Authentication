package rs.viveksingh.secure.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import rs.viveksingh.secure.model.User;
import org.springframework.stereotype.Service;
import rs.viveksingh.secure.repository.UserJpaRepository;

import java.util.Optional;


@Service
public class
UserService
{
   private  UserJpaRepository userJpaRepository;
   private  BCryptPasswordEncoder encoder=new BCryptPasswordEncoder(12);
   private AuthenticationManager authenticationManager;
   private JWTService jwtService;


    public UserService(UserJpaRepository userJpaRepository,AuthenticationManager authenticationManager,JWTService jwtService)
    {
        this.userJpaRepository = userJpaRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;

    }



    public Optional<User> findById(int id)
    {
        return userJpaRepository.findById(id);
    }

    public User saveUser (User user){
        user.setPassword(encoder.encode(user.getPassword()));
       return userJpaRepository.save(user);
    }
//    authenticationManager is an instance of AuthenticationManager, which is responsible for authenticating requests.
//    It delegates authentication to AuthenticationProvider (DaoAuthenticationProvider in database authentication).
//    If authentication is successful, it returns an Authentication object containing user details and roles.
    //this method basically authenticated the user object basically your object is signatured
    //UsernamePasswordAuthenticationToken ,it basically implements Authentication which is an interface
    //UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()) ,it creates a authentication request using provided username and password
    public String verify(User user) {
        //this step will verify that user exists in the database or not
      Authentication authentication=authenticationManager
              .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));

      //if user is authenticated it generates and returns the token
      if(authentication.isAuthenticated()){
          return jwtService.generateToken(user.getUsername());
      }



      return "fail";
    }

//    public List<User> findAll(){
//        return userJpaRepository.findAll();
//    }
}
