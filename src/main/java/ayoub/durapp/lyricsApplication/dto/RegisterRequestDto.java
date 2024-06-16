package ayoub.durapp.lyricsApplication.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor @NoArgsConstructor
@Builder
public class RegisterRequestDto {

    private String username;
    private String email;
    private String password;
}
