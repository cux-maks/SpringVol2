package hw9.domain.Users;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Cascade;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private String user_id;

    @Column(columnDefinition = "varchar", length = 32)
    private String user_pw;

    @Column(columnDefinition = "varchar", length = 16)
    private String user_name;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @Builder.Default
    private List<Authority> roles = new ArrayList();

    public void setRoles(List<Authority> role) {
        this.roles = role;
        role.forEach(o -> o.setUsers(this));
    }
}
