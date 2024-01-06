package hw9.controller;

import hw9.domain.Users.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import hw9.service.UserService;
import hw9.service.UserServiceImpl;

import java.util.List;

@Controller
@RequestMapping(value="/users")
public class UserController {
    private UserService service;

    @Autowired
    public void setUserService(UserServiceImpl usi){
        this.service = usi;
    }

    @RequestMapping(value = "", method = RequestMethod.POST)
    @ResponseBody
    public Users CreateNewUser(@RequestBody Users newUser){
        return service.CreateUsers(newUser);
    }

    @RequestMapping(value = "", method = RequestMethod.PUT)
    @ResponseBody
    public Users UpdateUsersName(@RequestBody Users TargetUser){
        return service.UpdateUsers(TargetUser);
    }

    @RequestMapping(value = "", method = RequestMethod.GET)
    @ResponseBody
    public List<Users> FindAllUsers(){
        return service.findAllUsers();
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    @ResponseBody
    public Users FindUsers(@PathVariable(name = "id") String id){
        return service.findUsers(id);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    @ResponseBody
    public void DeleteUsers(@PathVariable(name = "id") String id){
        service.DeleteUsers(id);
    }
}
