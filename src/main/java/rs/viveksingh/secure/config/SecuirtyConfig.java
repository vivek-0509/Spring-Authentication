package rs.viveksingh.secure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecuirtyConfig {



    private UserDetailsService userDetailsService;
    private JwtFilter jwtFilter;

    public SecuirtyConfig(UserDetailsService userDetailsService,JwtFilter jwtFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//       Customizer<CsrfConfigurer<HttpSecurity>> customCsrf= new Customizer<CsrfConfigurer<HttpSecurity>>() {
//           @Override
//           public void customize(CsrfConfigurer<HttpSecurity> customizer) {
//               customizer.disable();
//           }
//       };
        http.csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/register","/login").permitAll()
                        .anyRequest().authenticated()
                ).httpBasic(Customizer.withDefaults()) //for basic auth username pass
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);//this is done because i basically want that my user should be first verified through jwt token then it should go user pass verification
        return http.build();
     }
     //Dao is basically a database authenticate provider
     //DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider which implements Authentication provider
     @Bean
     public AuthenticationProvider authenticationProvider() {
         DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
         provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
         provider.setUserDetailsService(userDetailsService);
         return provider;
     }
      //Authentication manager returns  authentication object if user is authenticated
     //Authentication manager is a interface
    //AuthenticationConfiguration has a method that provide AuthenticationManager
    //AuthenticationConfiguration is an auto-configured Spring class that provides an AuthenticationManager instance.
    //This method retrieves the default AuthenticationManager from Spring Security.
     @Bean
     public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
         return config.getAuthenticationManager();
     }


  /*   not actually connecting with database just checking the in memory saved user
    @Bean
    public UserDetailsService userDetailsService() {
        //User class extends UserDetails//
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("harsh")
                .password("h1234")
                .roles("ADMIN")
                .build();

        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("om")
                .password("o1234")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user1,user2); //it implements UserDetailManager which actually extends UserDetailedService
    } */
}
