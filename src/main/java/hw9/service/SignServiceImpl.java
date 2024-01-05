package hw9.service;

import hw9.DTO.SignRequest;
import hw9.DTO.SignResponse;
import hw9.domain.Users.Authority;
import hw9.domain.Users.Users;
import hw9.domain.Users.UsersRepository;
import hw9.security.JwtProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@Transactional
@RequiredArgsConstructor
public class SignServiceImpl implements SignService{

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @Override
    public SignResponse login(SignRequest request) throws Exception{
        Users user = usersRepository.findById(request.getId()).orElseThrow(() ->
                new BadCredentialsException("잘못된 계정정보 입니다."));
        if(!passwordEncoder.matches(request.getPassword(), user.getUser_pw())){
            throw new BadCredentialsException("잘못된 계정정보 입니다.");
        }

        return SignResponse.builder()
                .id(user.getUser_id())
                .name(user.getUser_name())
                .roles(user.getRoles())
                .token((jwtProvider.createToken(user.getUser_id(), user.getRoles())))
                .build();
    }

    public boolean register(SignRequest request) throws Exception {
        try {
            Users user = Users.builder()
                    .user_id(request.getId())
                    .user_pw(passwordEncoder.encode(request.getPassword()))
                    .user_name(request.getName())
                    .build();

            user.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));

            usersRepository.save(user);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new Exception("잘못된 요청입니다.");
        }
        return true;
    }

    @Override
    public SignResponse getUser(String id) throws Exception {
        Users user = usersRepository.findById(id)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new SignResponse(user);
    }

}
