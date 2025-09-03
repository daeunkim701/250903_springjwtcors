package com.example.springjwtcors.filter;

import com.example.springjwtcors.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.graphql.GraphQlProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    public JwtAuthorizationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // `Bearer {...}` 리허게 생긴 거 삭제 날려버려야 함
        String token = resolveToken(request);

        // Text가 null이거나 empty인지 확인, empty가 아니면 true
        if (StringUtils.hasText(token) && jwtUtil.validateToken(token)) {
            String username = jwtUtil.getUsernameFromToken(token);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }


        //이게 맨 뒤에 잘 위치해야 함
        filterChain.doFilter(request, response);
    }

    private final JwtUtil jwtUtil;

    // Bearer을 제거하고 Authorization을 Header로부터 읽어주기
    private final String AUTHORIZATION_HEADER = "Authorization";
    private final String BEARER_PREFIX = "Bearer";
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            // substring (앞[포함] 뒤[불포함])
            // return bearerToken.substring(7);
            // 123456789
            // substring(7) 결과 -> 89
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
