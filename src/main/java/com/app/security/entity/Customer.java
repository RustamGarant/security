package com.app.security.entity;

import jakarta.persistence.*;
import java.util.*;
import lombok.*;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(schema = "user_management", name = "t_user")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "c_user")
    private String username;

    @Column(name = "c_password")
    private String password;

    @ManyToMany
    @JoinTable(schema = "user_management", name = "t_user_authority",
    joinColumns = @JoinColumn(name = "id_user"),
    inverseJoinColumns = @JoinColumn(name = "id_authority"))
    private List<Authority> authorities;

}
