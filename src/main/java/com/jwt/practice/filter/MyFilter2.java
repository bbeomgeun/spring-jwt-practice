package com.jwt.practice.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터 2");
        chain.doFilter(request, response); // 끝나지말고 계속 프로그램 프로세스가 진행되도록
    }
}
