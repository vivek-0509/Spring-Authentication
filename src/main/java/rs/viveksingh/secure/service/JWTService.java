package rs.viveksingh.secure.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static jdk.jfr.internal.EventWriterKey.getKey;
//Handles JWT extraction & validation.
@Service
public class
JWTService {

    private String secretkey="";

    //this is used to generate the key
    public JWTService(){
        try{
            KeyGenerator keyGen= KeyGenerator.getInstance("HmacSHA256");//we are using HmacSHA256 algorithm to generate a key
            SecretKey sk= keyGen.generateKey();
            secretkey= Base64.getEncoder().encodeToString(sk.getEncoded()); //it converts the key into string form
        }catch(NoSuchAlgorithmException e){
           throw new RuntimeException(e);
        }

    }

    //jwts is a class that we got from jsonwebtoken package
    // and it has various methods to generate a token

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)   //all this things mentioned below  are to be claimed  in our token
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 30))
                .and()
                .signWith(getKey()) //here we are signing and for signing we need key so we are generating the key
                .compact();

    }

    private SecretKey getKey(){
        //converting string into bytes because it accepts 64 bytes not direct string
        byte[] keyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //claims is basically a minterface that implements Map through which we can extract the claims that we saved in our map

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims =extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName=extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
