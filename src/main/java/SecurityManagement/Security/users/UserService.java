package SecurityManagement.Security.users;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

 private final PasswordEncoder passwordEncoder;
 private final UserRepository userrepository;

 public void changePassword(ChangePasswordRequest request, Principal connectedUser){

     var user = (User)((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

     if(!passwordEncoder.matches(request.getCurrentPassword(),user.getPassword())){
         throw new IllegalMonitorStateException("Wrong password");
     }
     if(!request.getNewPassword().equals(request.getConfirmationPassword())){
         throw new IllegalMonitorStateException("Wrong password");
     }

     user.setPassword((passwordEncoder.encode(request.getNewPassword())));
     userrepository.save(user);

 }

}
