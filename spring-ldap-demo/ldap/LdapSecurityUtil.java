package com.jingoal.web.collegecms.security.ldap;

import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.jingoal.cache.CacheClient;

/**
 * Description: LDAP登录工具类
 */
@Component
public class LdapSecurityUtil {

  @Autowired
  @Qualifier("cacheClient")
  private CacheClient cacheClient;

  @Value("${ldap.sessionId}")
  private String ldapSessionId;

  /**
   * 退出登录
   * 
   * @param request
   * @param response
   *
   * @author zhangwang
   */
  public void logout(HttpServletRequest request, HttpServletResponse response) {
    Cookie cookie = WebUtils.getCookie(request, ldapSessionId);
    if (cookie != null) {
      cacheClient.remove0(cookie.getValue());
    }
    deleteCookie(response, ldapSessionId);
  }

  /**
   * 用户登录
   *
   * @param luser ldap用户对象
   * @param request
   * @param response
   *
   * @author zhangwang
   */
  public void login(LdapUser luser, HttpServletRequest request, HttpServletResponse response) {
    luser.setIp(getRemortIP(request));
    addCookieAndCache(response, luser);
  }

  private void addCookieAndCache(HttpServletResponse response, LdapUser ldapUser) {
    String lSessionId = generateValue();

    // 会话cookie
    Cookie cookie = new Cookie(ldapSessionId, lSessionId);
    cookie.setPath("/");
    cookie.setMaxAge(-1);
    cookie.setHttpOnly(true);
    response.addCookie(cookie);

    // 该账号是否已登录
    String existLoginCacheKey = "LDAP_RELOGIN_" + String.valueOf(ldapUser.getUid());
    String existLoginLsessionId = cacheClient.get(existLoginCacheKey);
    if (null != existLoginLsessionId) {
      // 将当前已登录的设置为登录失效（挤掉）
      LdapUser existLoginUser = cacheClient.get(existLoginLsessionId);
      if (null != existLoginUser) {
        existLoginUser.setLoginValid(false);
        // 设置失效后重新set，拦截器会判断是否重复登陆
        cacheClient.remove0(existLoginLsessionId);
        cacheClient.set(existLoginLsessionId, existLoginUser);
      }
      // 删掉旧的已登录用户
      cacheClient.remove0(existLoginCacheKey);
    }
    // 设置新的登录用户
    cacheClient.set(lSessionId, ldapUser);
    cacheClient.set(existLoginCacheKey, lSessionId);
  }

  public LdapUser authenticate(HttpServletRequest request) {
    LdapUser loginUser = null;
    Cookie cookie = WebUtils.getCookie(request, ldapSessionId);
    if (null != cookie) {
      String ldapSessionId = cookie.getValue();
      loginUser = cacheClient.get(ldapSessionId);
    }
    return loginUser;
  }

  public String getRemortIP(HttpServletRequest request) {
    if (request.getHeader("X-Forwarded-For") == null) {
      return request.getRemoteAddr();
    }
    return request.getHeader("X-Forwarded-For");
  }

  private void deleteCookie(HttpServletResponse response, String cookieName) {
    Cookie cookie = new Cookie(cookieName, "");
    cookie.setPath("/");
    cookie.setMaxAge(0);
    response.addCookie(cookie);
  }

  private String generateValue() {
    return UUID.randomUUID().toString();
  }
}