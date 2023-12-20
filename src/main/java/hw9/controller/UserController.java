package hw9.controller;

import hw9.domain.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import hw9.service.UserService;
import hw9.service.UserServiceImpl;

import java.util.ArrayList;

@Controller
@SpringBootApplication(scanBasePackages = "hw9")
@RequestMapping(value="/users")
public class UserController {
    private UserService service;

    public static void main(String[] args) {
        SpringApplication.run(UserController.class, args);
    }

    @Autowired
    public void setUserService(UserServiceImpl usi){
        this.service = usi;
    }

    @RequestMapping(value = "", method = RequestMethod.POST)
    @ResponseBody
    public Users CreateNewUser(Users newUser){
        return service.CreateUsers(newUser);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.POST)
    @ResponseBody
    public Users UpdateUsersName(@PathVariable(name = "id") String id, Users TargetUser){
        return service.UpdateUsers(id, TargetUser);
    }

    @RequestMapping(value = "", method = RequestMethod.GET)
    @ResponseBody
    public ArrayList<Users> FindAllUsers(){
        return service.findAllUsers();
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    @ResponseBody
    public Users FindUsers(@PathVariable(name = "id") String id){
        return service.findUsers(id);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    @ResponseBody
    public int DeleteUsers(@PathVariable(name = "id") String id){
        return service.DeleteUsers(id);
    }
}
