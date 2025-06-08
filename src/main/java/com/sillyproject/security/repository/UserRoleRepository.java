package com.sillyproject.security.repository;

import com.sillyproject.security.entity.Role;
import com.sillyproject.security.entity.User;
import com.sillyproject.security.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

    @Query(value = """
        SELECT r.name
        FROM roles r
        JOIN users_roles urm ON r.id = urm.role_id
        JOIN users u ON u.id = urm.user_id
        WHERE u.username = :username
        AND r.is_active = true
        AND :now BETWEEN urm.effective_start_date AND IFNULL(urm.effective_end_date, CURDATE())
    """, nativeQuery = true)
    List<String> findActiveRolesByUsername(@Param("username") String username, @Param("now") LocalDate now);

}
