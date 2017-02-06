package com.jingoal.web.collegecms.security.ldap;

import java.io.Serializable;

/**
 * Description: LdapUser用户实体
 */
public class LdapUser implements Serializable {

  private static final long serialVersionUID = -4871120950621634469L;

  private String uid;

  private String pwd;

  private String ip;

  private boolean loginValid = true;

  public String getUid() {
    return uid;
  }

  public void setUid(String uid) {
    this.uid = uid;
  }

  public String getPwd() {
    return pwd;
  }

  public void setPwd(String pwd) {
    this.pwd = pwd;
  }

  public String getIp() {
    return ip;
  }

  public void setIp(String ip) {
    this.ip = ip;
  }

  public boolean isLoginValid() {
    return loginValid;
  }

  public void setLoginValid(boolean loginValid) {
    this.loginValid = loginValid;
  }
}