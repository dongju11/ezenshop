package com.ezen.Vo;

/*
 * 
 * 
CREATE TABLE MEMBER(	
MEMBER_NO	 NUMBER NOT NULL PRIMARY KEY , 
MEMBER_ID	VARCHAR2(20) NOT NULL,
MEMBER_PW	VARCHAR2(100) NOT NULL,
MEMBER_NAME	VARCHAR2(20) NOT NULL,
MEMBER_PHONE	VARCHAR2(20) NOT NULL,
MEMBER_ADDR	VARCHAR2(300) NOT NULL,
MEMBER_BIRTH	VARCHAR2(15) NOT NULL,
MEMBER_EMAIL	VARCHAR2(30) NOT NULL
);	
CREATE SEQUENCE	MEMBER_NO_SEQ  
START WITH 1	
INCREMENT BY 1	 
NOMAXVALUE	
MINVALUE 1;	 
 * 
 * 
 */

public class MemberVO {
	
	private int MEMBER_NO;
	private String MEMBER_ID;
	private String MEMBER_PW;
	private String MEMBER_NAME;
	private String MEMBER_PHONE;
	private String MEMBER_ADDR;
	private String MEMBER_BIRTH;
	private String MEMBER_EMAIL;
	
	
	private int MEMBER_VERIFY;
	
	public int getMEMBER_VERIFY() {
		return MEMBER_VERIFY;
	}
	public void setMEMBER_VERIFY(int mEMBER_VERIFY) {
		MEMBER_VERIFY = mEMBER_VERIFY;
	}
	
	
	public int getMEMBER_NO() {
		return MEMBER_NO;
	}
	public void setMEMBER_NO(int mEMBER_NO) {
		MEMBER_NO = mEMBER_NO;
	}
	public String getMEMBER_ID() {
		return MEMBER_ID;
	}
	public void setMEMBER_ID(String mEMBER_ID) {
		MEMBER_ID = mEMBER_ID;
	}
	public String getMEMBER_PW() {
		return MEMBER_PW;
	}
	public void setMEMBER_PW(String mEMBER_PW) {
		MEMBER_PW = mEMBER_PW;
	}
	public String getMEMBER_NAME() {
		return MEMBER_NAME;
	}
	public void setMEMBER_NAME(String mEMBER_NAME) {
		MEMBER_NAME = mEMBER_NAME;
	}
	public String getMEMBER_PHONE() {
		return MEMBER_PHONE;
	}
	public void setMEMBER_PHONE(String mEMBER_PHONE) {
		MEMBER_PHONE = mEMBER_PHONE;
	}
	public String getMEMBER_ADDR() {
		return MEMBER_ADDR;
	}
	public void setMEMBER_ADDR(String mEMBER_ADDR) {
		MEMBER_ADDR = mEMBER_ADDR;
	}
	public String getMEMBER_BIRTH() {
		return MEMBER_BIRTH;
	}
	public void setMEMBER_BIRTH(String mEMBER_BIRTH) {
		MEMBER_BIRTH = mEMBER_BIRTH;
	}
	public String getMEMBER_EMAIL() {
		return MEMBER_EMAIL;
	}
	public void setMEMBER_EMAIL(String mEMBER_EMAIL) {
		MEMBER_EMAIL = mEMBER_EMAIL;
	}
	

}
