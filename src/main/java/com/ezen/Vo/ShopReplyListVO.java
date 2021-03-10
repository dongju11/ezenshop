package com.ezen.Vo;

import java.util.Date;

/*
 * SELECT r.GOODS_NO, r.MEMBER_ID, r.REP_NO, r.REP_CON, r.REP_DATE,r.REP_START, m.MEMBER_NAME
    from shop_reply r
        inner join MEMBER m
            on r.MEMBER_ID = m.MEMBER_ID
        where GOODS_NO = 24;
 * 
 * 
 */

public class ShopReplyListVO {
	
	private int GOODS_NO;
	private String MEMBER_ID;
	private int REP_NO;
	private String REP_CON;
	private Date REP_DATE;
	private int REP_START;
	private String MEMBER_NAME;
	
	public int getGOODS_NO() {
		return GOODS_NO;
	}
	public void setGOODS_NO(int gOODS_NO) {
		GOODS_NO = gOODS_NO;
	}
	public String getMEMBER_ID() {
		return MEMBER_ID;
	}
	public void setMEMBER_ID(String mEMBER_ID) {
		MEMBER_ID = mEMBER_ID;
	}
	public int getREP_NO() {
		return REP_NO;
	}
	public void setREP_NO(int rEP_NO) {
		REP_NO = rEP_NO;
	}
	public String getREP_CON() {
		return REP_CON;
	}
	public void setREP_CON(String rEP_CON) {
		REP_CON = rEP_CON;
	}
	public Date getREP_DATE() {
		return REP_DATE;
	}
	public void setREP_DATE(Date rEP_DATE) {
		REP_DATE = rEP_DATE;
	}
	public int getREP_START() {
		return REP_START;
	}
	public void setREP_START(int rEP_START) {
		REP_START = rEP_START;
	}
	public String getMEMBER_NAME() {
		return MEMBER_NAME;
	}
	public void setMEMBER_NAME(String mEMBER_NAME) {
		MEMBER_NAME = mEMBER_NAME;
	}

	
}
