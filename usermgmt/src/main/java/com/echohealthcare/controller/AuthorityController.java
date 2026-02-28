package com.echohealthcare.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.echohealthcare.model.Authority;
import com.echohealthcare.service.AuthorityService;

@RestController
public class AuthorityController {

    private final AuthorityService authorityService;

    public AuthorityController(AuthorityService authorityService) {
        this.authorityService = authorityService;
    }

    @GetMapping("/authority")
    public List<Authority> getAllAuthorities() {
        return authorityService.findAllAuthorities();
    }
}
