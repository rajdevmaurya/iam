package com.echohealthcare.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.echohealthcare.model.Role;
import com.echohealthcare.service.RoleService;

@RestController
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping("/role")
    public List<Role> getAllRoles() {
        return roleService.findAllRoles();
    }
}
