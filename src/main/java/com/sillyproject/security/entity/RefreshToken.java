package com.sillyproject.security.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_tokens", uniqueConstraints = {
        @UniqueConstraint(columnNames = "token_hash")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;


    @Column(name = "token_hash", nullable = false, length = 128, unique = true)
    private String tokenHash;

    /**
     * JWT ID (jti) claim of the refresh token. Useful for audit/rotation/reuse detection.
     */
    @Column(name = "jti", nullable = false, length = 64)
    private String jti;

    @Column(name = "expiry_date", nullable = false)
    private Date expiryDate;

    @Column(name = "created_at")
    private Date createdAt;

    @Column(name = "revoked")
    private boolean revoked = false;

    @Column(name = "revoked_at")
    private Date revokedAt;
}
