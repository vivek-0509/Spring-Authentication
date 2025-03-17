package rs.viveksingh.secure.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.core.ApplicationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import rs.viveksingh.secure.service.JWTService;
import rs.viveksingh.secure.service.MyUserDetailsService;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private JWTService jwtService;
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    public JwtFilter( JWTService jwtService, MyUserDetailsService myUserDetailsService ) {
        this.jwtService = jwtService;
        this.myUserDetailsService = myUserDetailsService;
    }

    //it extracts, validates, and processes the JWT token.
    //HttpServletRequest request have response that we got from the user it also contains the authorization header
    //HttpServletResponse response , represents the response sent back to the client
    //FilterChain filterChain ,calls the next filter in the Spring Security filter chain or forwards the request to the controller
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
         //we get token in the form of (Bearer tokenvalue) from the user we have to cut the bearer part
        //token comes in the request header
        //we only need Authorization header
        String authHeader = request.getHeader("Authorization");
        String  token = null;
        String username=null;

        if(authHeader != null && authHeader.startsWith("Bearer ")) { //checking if header is not null and has bearer  token or not
            token = authHeader.substring(7); //since we need to cut the bearer part
            username=jwtService.extractUserName(token); //extract username from JWT
        }


        //prevents redundant authentication if the user is already authenticated
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {//we are checking that the token/object is already authenticated or not ,if not authenticated then only we will authenticate else we will just validate it
            //will give me the entire Userdetail object
            //Loads user details for authentication from database(username,password,roles)
            UserDetails userDetails= myUserDetailsService.loadUserByUsername(username);

           //jwtService.validateToken(token,userDetails ), verify if the JWT is valid ,ensure the token belongs to the correct user
            if(jwtService.validateToken(token,userDetails)){

                //Creates a UsernamePasswordAuthenticationToken to store authentication details. passes:
//                userDetails =The authenticated user.
//                null = No credentials required.
//                 userDetails.getAuthorities() = User's roles/permissions.
                 UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // Attaches request details to the authentication object.
                //Stores the authenticated user in SecurityContextHolder
                 authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                 //security context holder holds the authenticated user details
                //so that we dont need to authnticate the user for every request
                 SecurityContextHolder.getContext().setAuthentication(authToken);
            }
             //passing the request to next filter or controller

        }
        filterChain.doFilter(request, response);
    }
}
