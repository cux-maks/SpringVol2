package hw9.controller;

import hw9.DTO.SignRequest;
import hw9.DTO.SignResponse;
import hw9.domain.Users.UsersRepository;
import hw9.service.SignServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping(value="/sign")
public class SignController {

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
    @PostMapping(value = "/login")
    public ResponseEntity<SignResponse> signin(@RequestBody SignRequest request) throws Exception{
        return new ResponseEntity<>(signService.login(request), HttpStatus.OK);
    }

    @PostMapping(value = "/register")
    public ResponseEntity<Boolean> signup(@RequestBody SignRequest request) throws Exception{
        return new ResponseEntity<>(signService.register(request), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<SignResponse> getUserForAdmin(@RequestParam String id) throws Exception {
        return new ResponseEntity<>(signService.getUser(id), HttpStatus.OK);
    }

}
