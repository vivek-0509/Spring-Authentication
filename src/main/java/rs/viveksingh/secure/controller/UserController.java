package rs.viveksingh.secure.controller;
import io.jsonwebtoken.JwtBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.viveksingh.secure.model.User;
import rs.viveksingh.secure.service.UserService;

import java.util.Optional;

@RestController
//this defines base path
//@RequestMapping("/auth")

public class UserController {

    UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/{id}")
    public Optional<User> getUserById(@PathVariable int id)
    {
        return userService.findById(id);
    }
    @GetMapping("/")
    public String Hello()
    {
        return "Hello World";
    }

//    @GetMapping("/users")
//    public List<User> getAllUsers() {
//        return userService.findAll();
//    }
    
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user){
        userService.saveUser(user);
        
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public String login(@RequestBody User user){
        return userService.verify(user);
    }
}
