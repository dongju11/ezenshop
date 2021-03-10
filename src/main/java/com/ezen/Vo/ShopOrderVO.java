package com.ezen.Vo;

import java.util.Date;

public class ShopOrderVO {
	/*
    create table SHOP_ORDER (
ORDER_ID    varchar2(50) not null,
MEMBER_ID    varchar2(50) not null,
ORDER_REC    varchar2(50) not null,
MEMBER_ADDR   varchar2(20) not null,
ORDER_PHON   varchar2(30) not null,
ORDER_AMOUNT      number       not null,
ORDER_DATE   Date         default sysdate,   
primary key(ORDER_ID)
);
*/
	
	private String ORDER_ID;
	private String MEMBER_ID;
	private String ORDER_REC;
	private String MEMBER_ADDR;
	private String ORDER_PHON;
	private int ORDER_AMOUNT;
	private Date ORDER_DATE;
	
	private String ORDER_DELIVERY;
	
	
	public String getORDER_DELIVERY() {
		return ORDER_DELIVERY;
	}
	public void setORDER_DELIVERY(String oRDER_DELIVERY) {
		ORDER_DELIVERY = oRDER_DELIVERY;
	}
	public String getORDER_ID() {
		return ORDER_ID;
	}
	public void setORDER_ID(String oRDER_ID) {
		ORDER_ID = oRDER_ID;
	}
	public String getMEMBER_ID() {
		return MEMBER_ID;
	}
	public void setMEMBER_ID(String mEMBER_ID) {
		MEMBER_ID = mEMBER_ID;
	}
	public String getORDER_REC() {
		return ORDER_REC;
	}
	public void setORDER_REC(String oRDER_REC) {
		ORDER_REC = oRDER_REC;
	}
	public String getMEMBER_ADDR() {
		return MEMBER_ADDR;
	}
	public void setMEMBER_ADDR(String mEMBER_ADDR) {
		MEMBER_ADDR = mEMBER_ADDR;
	}
	public String getORDER_PHON() {
		return ORDER_PHON;
	}
	public void setORDER_PHON(String oRDER_PHON) {
		ORDER_PHON = oRDER_PHON;
	}
	public int getORDER_AMOUNT() {
		return ORDER_AMOUNT;
	}
	public void setORDER_AMOUNT(int oRDER_AMOUNT) {
		ORDER_AMOUNT = oRDER_AMOUNT;
	}
	public Date getORDER_DATE() {
		return ORDER_DATE;
	}
	public void setORDER_DATE(Date oRDER_DATE) {
		ORDER_DATE = oRDER_DATE;
	}
	
	
}
