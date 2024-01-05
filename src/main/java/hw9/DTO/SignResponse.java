package hw9.DTO;

import hw9.domain.Users.Authority;
import hw9.domain.Users.Users;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignResponse {
    private String id;
    private String password;
    private String name;
    private List<Authority> roles = new ArrayList<>();
    private String token;

    public SignResponse(Users user){
        this.id = user.getUser_id();
        this.password = user.getUser_pw();
        this.name = user.getUser_name();
        this.roles = user.getRoles();
    }
}
