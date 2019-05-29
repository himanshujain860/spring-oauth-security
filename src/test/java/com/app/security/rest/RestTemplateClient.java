package com.app.security.rest;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

public class RestTemplateClient {

    private static final String REST_SERVICE_URI = "http://localhost:8080/";

    private static HttpHeaders getHeaders(){
        String plainCredentials="admin:password";
        String base64Credentials = new String(Base64.encodeBase64(plainCredentials.getBytes()));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Basic " + base64Credentials);
        List<MediaType> list = new ArrayList<>();
        list.add(MediaType.APPLICATION_JSON);
        headers.setAccept(list);
        return headers;
    }

    private static void listAllUsers(){
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> request = new HttpEntity<>(getHeaders());
        ResponseEntity<String> response = restTemplate.exchange(REST_SERVICE_URI, HttpMethod.GET, request, String.class);
        System.out.println(response);
    }

    public static void main(String[] args) {
        listAllUsers();
    }
}
