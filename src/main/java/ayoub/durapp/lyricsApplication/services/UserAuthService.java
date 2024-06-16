package ayoub.durapp.lyricsApplication.services;

import ayoub.durapp.lyricsApplication.dto.RegisterRequestDto;
import ayoub.durapp.lyricsApplication.model.UserInfo;
import ayoub.durapp.lyricsApplication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserAuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserInfo registerNewUser(RegisterRequestDto userInfo) {
        // Vérifier si l'utilisateur existe déjà
        if (userRepository.findByUsername(userInfo.getUsername()) != null) {
            throw new IllegalArgumentException("Username already exists");
        }
        // Créer un nouvel utilisateur avec un mot de passe encodé
        UserInfo newUser = new UserInfo().builder().email(userInfo.getEmail()).username(userInfo.getUsername()).password(userInfo.getPassword()).build();
        return userRepository.save(newUser);
    }
}
