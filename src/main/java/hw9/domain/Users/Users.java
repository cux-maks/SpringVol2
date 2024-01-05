package hw9.domain.Users;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class Users {

    @Id
    @Column(columnDefinition = "int")
    private Integer user_id;

    @Column(columnDefinition = "varchar", length = 32)
    private String user_pw;

    @Column(columnDefinition = "varchar", length = 16)
    private String user_name;

    @Builder
    public Users(Integer UserId, String UserPw, String UserName){
        this.user_id = UserId;
        this.user_pw = UserPw;
        this.user_name = UserName;
    }
}
