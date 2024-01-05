package hw9.domain.Users;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = UsersRepository.class)
@EnableJpaRepositories(basePackages = "hw9.domain")
@SpringBootTest
class UsersRepositoryTest {

    @Autowired
    UsersRepository usersRepository;

    @AfterEach
    public void cleanup(){
        usersRepository.deleteAll();
    }

    @Test
    public void 불러오기(){
        String id = "바보바보";
        String pw = "1233asdf";
        String name = "jbh";

        usersRepository.save(Users.builder()
                .UserId(id)
                .UserPw(pw)
                .UserName(name)
                .build());

        List<Users> usersList = usersRepository.findAll();

//        for (Users u: usersList){
//            System.out.println(u.toString());
//        }

    }

}