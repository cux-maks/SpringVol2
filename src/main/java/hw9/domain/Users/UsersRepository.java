package hw9.domain.Users;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {

    @Query("select u from Users u where u.user_id = :user_id")
    Optional<Users> findByUserId(String user_id);

    @Transactional
    @Modifying
    @Query("delete from Users u where u.user_id = :user_id")
    void deleteByUser_id(String user_id);
}