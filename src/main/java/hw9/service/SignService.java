package hw9.service;

import hw9.DTO.SignRequest;
import hw9.DTO.SignResponse;

public interface SignService {
    public SignResponse login(SignRequest request) throws Exception;
    public boolean register(SignRequest request) throws Exception;
    public SignResponse getUser(String id) throws  Exception;
}
