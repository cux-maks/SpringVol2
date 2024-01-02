package hw9.service;

import hw9.domain.Users.Users;
import hw9.domain.Users.UsersRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
public class UserServiceImpl implements UserService{

    private final UsersRepository repository;

    @Autowired
    public UserServiceImpl(UsersRepository repository) {
        this.repository = repository;
    }

    @Override
    public Users CreateUsers(Users newUser){

        repository.save(Users.builder()
                .UserId(newUser.getUser_id())
                .UserPw(newUser.getUser_pw())
                .UserName(newUser.getUser_name()).build());

        return newUser;
    }

    @Override
    public List<Users> findAllUsers(){

        return repository.findAll();

    };

    @Override
    public Users findUsers(Integer id){

        return repository.findById(id).orElse(new Users(null, null, null));

    };

    @Override
    public void DeleteUsers(Integer id){

        repository.deleteById(id);

    };

    @Override
    public Users UpdateUsers(Users TargetUser){

        repository.save(Users.builder()
                .UserName(TargetUser.getUser_name())
                .UserId(TargetUser.getUser_id())
                .UserPw(TargetUser.getUser_pw())
                .build());

        return TargetUser;
    };


}
