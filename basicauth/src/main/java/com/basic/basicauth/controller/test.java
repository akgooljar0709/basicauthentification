package com.basic.basicauth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class test {

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String getUser() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        System.out.println(currentPrincipalName);

        return "Hello, user!";

    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public String getAdmin() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        System.out.println(currentPrincipalName);
        return "Hello, Admin!";

    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('moderator')")
    public String getMod() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        System.out.println(currentPrincipalName);
        return "Hello, Moderator!";

    }
}
