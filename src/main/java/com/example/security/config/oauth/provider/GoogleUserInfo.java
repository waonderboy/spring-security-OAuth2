package com.example.security.config.oauth.provider;

import java.util.Map;

public class GoogleUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes; // oAuth2User.getAttributes();

//    log.info("userRequest.getAttributes={}", oAuth2User.getAttributes());
//    String provider = userRequest.getClientRegistration().getRegistrationId(); // google
//    String providerId = oAuth2User.getAttribute("sub");
//    String username = provider + "_" + providerId;
//    String password = bCryptPasswordEncoder.encode("getinthere");
//    String email = oAuth2User.getAttribute("email");
//    String role = oAuth2User.getAuthorities().stream().findFirst().get().getAuthority();

    public GoogleUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
