package com.echohealthcare.model;

import java.util.List;

public record User(
        String username,
        String password,
        Boolean enabled,
        List<String> authority) {

}
