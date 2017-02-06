package com.jingoal.web.collegecms.security.ldap;

import java.util.List;

import javax.naming.directory.DirContext;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.stereotype.Component;

import com.jingoal.web.common.rest.exception.RestCommonException;
import com.jingoal.web.common.rest.exception.RestExceptionValue;


/**
 * Description: ldap数据库访问工具类，用于登录校验
 */
@Component
public class LdapDBUtils {

  private static final Logger logger = LoggerFactory.getLogger(LdapDBUtils.class);

  @Autowired(required = false)
  private LdapTemplate ldapTemplate;

  /**
   * 验证用户登陆
   * 
   * @param uid 用户uid
   * @param password 用户密码
   * 
   */
  @SuppressWarnings("rawtypes")
  public boolean checkLogin(LdapUser ldapUser) {

    // 用户名为空
    if (StringUtils.isBlank(ldapUser.getUid())) {
      throw new RestCommonException(RestExceptionValue.LOGINNAME_EMPTY_ERROR);
    }
    // 密码为空
    if (StringUtils.isBlank(ldapUser.getPwd())) {
      throw new RestCommonException(RestExceptionValue.LOGINPASSWORD_EMPTY_ERROR);
    }

    // 获取用户 id 所在 ldap 中的 user dn
    List dnlist = getUserDnByUid(ldapUser.getUid());
    // 根据查询到的所有 dn 遍历，检查是否某一 user dn 与用户密码可以登陆 ldap
    for (Object dn : dnlist) {
      if (checkUdnAndpwd(dn.toString(), ldapUser.getPwd())) {
        return true;
      }
    }

    // 登录失败：用户名或密码错误
    throw new RestCommonException(RestExceptionValue.AUTHEN_ERROR);
  }

  /**
   * 查询用户 user dn
   * 
   * @param uid 用户id
   * 
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  private List getUserDnByUid(String uid) {
    AndFilter andFilter = new AndFilter();
    andFilter.and(new EqualsFilter("uid", uid));
    List result = ldapTemplate.search("", andFilter.encode(), new AbstractContextMapper() {
      protected Object doMapFromContext(DirContextOperations ctx) {
        return ctx.getNameInNamespace();
      }
    });
    return result;
  }

  /**
   * 登陆验证
   * 
   * @param userDn 用户的user dn
   * @param password 用户登陆密码
   * 
   */
  private boolean checkUdnAndpwd(String userDn, String password) {
    DirContext ctx = null;
    try {
      ctx = ldapTemplate.getContextSource().getContext(userDn, password);
      return true;
    } catch (Exception e) {
      logger.error("ldap login failue!");
      return false;
    } finally {
      LdapUtils.closeContext(ctx);
    }
  }
}