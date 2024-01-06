package hw9.service;

import hw9.domain.Users.Users;

import java.util.List;

public interface UserService {
    public Users CreateUsers(Users newUser);
    public List<Users> findAllUsers();
    public Users findUsers(String id);
    public void DeleteUsers(String id);
    public Users UpdateUsers(Users TargetUser);
}