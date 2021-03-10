package com.ezen.Vo;

import java.util.Date;

public class CartVO {
/*
	CREATE TABLE CART (
		    CART_NO number not null,
		    MEMBER_ID VARCHAR2(50) not null,
		    GOODS_NO number not null,
		    cartSTATUS   number          not null,
		    addDate     date            default sysdate,
		    primary key(CART_NO, MEMBER_ID) 
		);
*/
	
	private int CART_NO;
	private String MEMBER_ID;
	private int GOODS_NO;
	private int CARTSTATUS;
	private Date ADDDATE;
	public int getCART_NO() {
		return CART_NO;
	}
	public void setCART_NO(int cART_NO) {
		CART_NO = cART_NO;
	}
	public String getMEMBER_ID() {
		return MEMBER_ID;
	}
	public void setMEMBER_ID(String mEMBER_ID) {
		MEMBER_ID = mEMBER_ID;
	}
	public int getGOODS_NO() {
		return GOODS_NO;
	}
	public void setGOODS_NO(int gOODS_NO) {
		GOODS_NO = gOODS_NO;
	}
	public int getCARTSTATUS() {
		return CARTSTATUS;
	}
	public void setCARTSTATUS(int cARTSTATUS) {
		CARTSTATUS = cARTSTATUS;
	}
	public Date getADDDATE() {
		return ADDDATE;
	}
	public void setADDDATE(Date aDDDATE) {
		ADDDATE = aDDDATE;
	}
	
}
