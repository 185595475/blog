package com.jingoal.web.collegecms.action;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.jingoal.web.college.iface.ICollege;
import com.jingoal.web.collegecms.security.CollegeSecurityUtil;
import com.jingoal.web.collegecms.security.ldap.LdapDBUtils;
import com.jingoal.web.collegecms.security.ldap.LdapSecurityUtil;
import com.jingoal.web.collegecms.security.ldap.LdapUser;
import com.jingoal.web.common.core.response.model.RestResponse;
import com.jingoal.web.common.open.AuthUser;

/**
 * Description: 目标学院CMS系统web入口
 */
@Controller
@RequestMapping("/v1")
public class LdapController extends BaseController {

  @Autowired
  private LdapSecurityUtil ldapSecurityUtil;
  @Autowired
  private LdapDBUtils ldapDBUtils;

  @Value("${sso.ssoURL}")
  private String ssoURL;

  /**
   * 退出登录,同时返回SSO退出登录的地址
   */
  @RequestMapping(value = "/logout")
  @ResponseBody
  public String logout(HttpServletRequest request, HttpServletResponse response) {
    ldapSecurityUtil.logout(request, response);
    return ssoURL + "logout";
  }

  /**
   * 错误页面：资源未找到页面
   */
  @RequestMapping("/resourceNotFound")
  public String resourceNotFound() {
    return "/public/404";
  }

  /**
   * CMS后台执行redis操作，只允许执行 get set del某一个目标学院的key
   *
   * @param cmd
   * @param key
   * @param value
   * @return 执行结果
   * @author xiongping
   */
  @RequestMapping("/excute/{cmd}")
  @ResponseBody
  public Object redisExcute(@PathVariable("cmd") String cmd, String key, String value) {
    if (StringUtils.isBlank(key)) {
      return "error. key is blank";
    }
    AuthUser authUser = CollegeSecurityUtil.getCurrentAuthUser();
    // 只允许执行 get set del
    if ("s".equalsIgnoreCase(cmd)) {
      if (StringUtils.isBlank(value)) {
        return "error. set value is blank";
      }
      return iCollege.redisExcute(authUser, "set", key, new String[] {value});
    } else if ("d".equalsIgnoreCase(cmd)) {
      return iCollege.redisExcute(authUser, "del", key);
    } else if ("g".equalsIgnoreCase(cmd)) {
      return iCollege.redisExcute(authUser, "get", key);
    } else {
      return "error. cmd must be [get set del]";
    }
  }

  /**
   * ldap 登录入口
   */
  @RequestMapping(value = "/ldap/toLogin")
  public String ldapToLogin() {
    return "/ldap/login";
  }

  /**
   * 退出登录,同时重定向到 ldap 登录页
   */
  @SuppressWarnings("rawtypes")
  @RequestMapping(value = "/ldap/login", method = RequestMethod.POST)
  @ResponseBody
  public RestResponse ldapLogin(@RequestBody LdapUser ldapUser, HttpServletRequest request,
      HttpServletResponse response) {

    ldapDBUtils.checkLogin(ldapUser);
    ldapSecurityUtil.login(ldapUser, request, response);
    return new RestResponse<>(RestResponse.SUCCESS_CODE);
  }
}