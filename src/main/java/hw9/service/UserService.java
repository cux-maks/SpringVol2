package hw9.service;

import hw9.domain.Users;

import java.util.ArrayList;

public interface UserService {
    public Users CreateUsers(Users newUser);
    public ArrayList<Users> findAllUsers();
    public Users findUsers(String id);
    public int DeleteUsers(String id);
    public Users UpdateUsers(String id, Users TargetUser);
}