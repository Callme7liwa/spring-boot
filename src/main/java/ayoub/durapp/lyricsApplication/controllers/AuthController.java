package ayoub.durapp.lyricsApplication.controllers;

import ayoub.durapp.lyricsApplication.dto.AuthRequestDTO;
import ayoub.durapp.lyricsApplication.dto.JwtResponseDTO;
import ayoub.durapp.lyricsApplication.dto.RegisterRequestDto;
import ayoub.durapp.lyricsApplication.model.UserInfo;
import ayoub.durapp.lyricsApplication.services.JwtService;
import ayoub.durapp.lyricsApplication.services.UserAuthService;
import ayoub.durapp.lyricsApplication.services.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController()
@RequestMapping("/api/v1/public/")
public class AuthController {

    AuthenticationManager authenticationManager ;
    JwtService jwtService;
    UserAuthService userAuthService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);



    AuthController(AuthenticationManager authenticationManager, JwtService jwtService, UserAuthService userAuthService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userAuthService = userAuthService;
    }

    @PostMapping("login")
    public JwtResponseDTO AuthenticateAndGetToken(@RequestBody AuthRequestDTO authRequestDTO){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequestDTO.getUsername(), authRequestDTO.getPassword()));
        logger.info("im after authnetication");
        if(authentication.isAuthenticated()){
            return JwtResponseDTO
                    .builder()
                    .accessToken(jwtService.GenerateToken(authRequestDTO.getUsername()))
                    .build();
        } else {
            throw new UsernameNotFoundException("invalid user request..!!");
        }
    }

    @PostMapping("register")
    public UserInfo  Register(@RequestBody RegisterRequestDto userInfo){
        return userAuthService.registerNewUser(userInfo);
    }

    @GetMapping("register")
    public String  Register(){
        return "register page";
    }

    @GetMapping("getHelloWorld")
    public String getHelloWorld(){
        return  "Hello World!";
    }

}
