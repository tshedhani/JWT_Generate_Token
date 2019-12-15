package com.example.db.dto;

import java.io.Serializable;
import java.sql.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="login_Iinfo", schema = "spring")
public class LoginInfo implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "login_id")
	private Integer loginId;

	@Column(name = "login_name")
	private String loginName;

	@Column(name = "login_password")
	private String loginPassword;

	@Column(name = "login_updated_date")
	private Date loginUpdatedDate;

	public Integer getLoginId() {
		return loginId;
	}

	public void setLoginId(Integer loginId) {
		this.loginId = loginId;
	}

	public String getLoginName() {
		return loginName;
	}

	public void setLoginName(String loginName) {
		this.loginName = loginName;
	}

	public String getLoginPassword() {
		return loginPassword;
	}

	public void setLoginPassword(String loginPassword) {
		this.loginPassword = loginPassword;
	}

	public Date getLoginUpdatedDate() {
		return loginUpdatedDate;
	}

	public void setLoginUpdatedDate(Date loginUpdatedDate) {
		this.loginUpdatedDate = loginUpdatedDate;
	}

	@Override
	public String toString() {
		return "LoginInfo [loginId=" + loginId + ", loginName=" + loginName + ", loginPassword=" + loginPassword
				+ ", loginUpdatedDate=" + loginUpdatedDate + "]";
	}
}
