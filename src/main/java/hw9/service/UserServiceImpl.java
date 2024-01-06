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
                .user_id(newUser.getUser_id())
                .user_pw(newUser.getUser_pw())
                .user_name(newUser.getUser_name()).build());

        return newUser;
    }

    @Override
    public List<Users> findAllUsers(){

        return repository.findAll();

    };

    @Override
    public Users findUsers(String id){

        return repository.findByUserId(id).orElse(new Users(null, null, null, null, null));

    };

    @Override
    public void DeleteUsers(String id){

        repository.deleteByUser_id(id);

    };

    @Override
    public Users UpdateUsers(Users TargetUser){

        repository.save(Users.builder()
                .user_name(TargetUser.getUser_name())
                .user_id(TargetUser.getUser_id())
                .user_pw(TargetUser.getUser_pw())
                .build());

        return TargetUser;
    };


}
