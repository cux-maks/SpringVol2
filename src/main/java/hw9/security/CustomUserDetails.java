package hw9.security;

import hw9.domain.Users.Users;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private final Users user;

    public CustomUserDetails(Users user){
        this.user = user;
    }

    public final Users getUsers(){
        return user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        return user.getRoles().stream().map(o -> new SimpleGrantedAuthority(o.getName())).collect(Collectors.toList());
    }

    @Override
    public String getPassword(){
        return user.getUser_pw();
    }

    @Override
    public String getUsername(){
        return user.getUser_name();
    }

    @Override
    public boolean isAccountNonExpired(){
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
