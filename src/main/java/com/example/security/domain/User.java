package com.example.security.domain;

import lombok.Builder;
import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Entity
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role;
    private LocalDateTime createdDate;

    private String provider;
    private String providerId;

    @Builder
    public User(int id, String username, String password, String email, String role, LocalDateTime createdDate, String provider, String providerId) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.createdDate = createdDate;
        this.provider = provider;
        this.providerId = providerId;
    }

    public User() {

    }
}
