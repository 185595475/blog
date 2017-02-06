package com.jingoal.web.collegecms.security.ldap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;

import com.jingoal.web.common.frontend.security.web.WebSecurityInterceptor;
import com.jingoal.web.common.rest.exception.RestCommonException;
import com.jingoal.web.common.rest.exception.RestExceptionValue;

/**
 * Description: 目标学院LDAP权限拦截器
 */
public class LdapSecurityInterceptor extends WebSecurityInterceptor {

  @Autowired
  private LdapSecurityUtil ldapSecurityUtil;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {

    LdapUser lau = ldapSecurityUtil.authenticate(request);
    String currIp = ldapSecurityUtil.getRemortIP(request);

    // 用户认证失败
    if (null == lau || !lau.isLoginValid() || !currIp.equals(lau.getIp())) {
      if ("XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"))) {
        // AJAX 抛出 401
        throw new RestCommonException(RestExceptionValue.AUTHEN_ERROR);
      } else {
        response.sendRedirect(request.getContextPath() + "/v1/ldap/toLogin");
        return false;
      }
    }

    return super.preHandle(request, response, handler);
  }
}