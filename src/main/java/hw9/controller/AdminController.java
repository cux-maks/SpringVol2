package hw9.controller;

import hw9.DTO.SignResponse;
import hw9.domain.Users.UsersRepository;
import hw9.service.SignServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value="/admin")
public class AdminController {

    private UsersRepository usersRepository;
    private SignServiceImpl signService;

    @Autowired
    public void setSignService(SignServiceImpl ssi){
        this.signService = ssi;
    }

    @Autowired
    public void setUsersRepository(UsersRepository ur){
        this.usersRepository = ur;
    }

    @GetMapping(value = "")
    public ResponseEntity<SignResponse> getUserForAdmin(@RequestParam String id) throws Exception {
        return new ResponseEntity<>(signService.getUser(id), HttpStatus.OK);
    }

}
