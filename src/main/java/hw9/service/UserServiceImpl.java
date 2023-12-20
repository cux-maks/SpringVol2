package hw9.service;

import hw9.domain.Users;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import hw9.repository.UserRepository;

import java.sql.SQLException;
import java.util.ArrayList;

@Slf4j
@Service
public class UserServiceImpl implements UserService{
    private UserRepository repository = new UserRepository();

    @Override
    public Users CreateUsers(Users newUser){
        Users resUsers = new Users();
        try {
            resUsers = repository.CreateUsers(newUser);
        }catch (SQLException e){
            log.error("service.CreateUsers error={}", e); // Exception 발생 시 로그
        }
        return resUsers;
    };

    @Override
    public ArrayList<Users> findAllUsers(){
        ArrayList<Users> resUsers = new ArrayList<>();
        try{
            resUsers = repository.findAllUsers();
        }catch(SQLException e){
            log.error("service.findAllUsers error = {}", e);
        }
        return resUsers;
    };

    @Override
    public Users findUsers(String id){
        Users resUsers = new Users();
        try {
            resUsers = repository.findUsers(id);
        }catch (SQLException e){
            log.error("service.findUsers error={}", e); // Exception 발생 시 로그
        }
        return resUsers;
    };

    @Override
    public int DeleteUsers(String id){
        int resUsers = 0;
        try {
            resUsers = repository.DeleteUser(id);
        }catch (SQLException e){
            log.error("service.DeleteUser error={}", e); // Exception 발생 시 로그
        }
        return resUsers;
    };

    @Override
    public Users UpdateUsers(String id, Users TargetUser){
        Users resUsers = new Users();
        try {
            resUsers = repository.UpdateUser(id, TargetUser);
        }catch (SQLException e){
            log.error("service.DeleteUser error={}", e); // Exception 발생 시 로그
        }
        return resUsers;
    };


}
