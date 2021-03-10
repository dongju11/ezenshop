package com.ezen.Vo;

import java.util.Date;

public class ShopReplyVO {
	
	/*
	 * create table SHOP_REPLY (
    GOODS_NO      number          not null,
    MEMBER_ID      varchar2(50)    not null,
    REP_NO      number          not null,
    REP_CON      varchar2(2000)  not null,
    REP_DATE     date            default sysdate,
    REP_START	number 			not null,
    primary key(GOODS_NO, REP_NO) 
);
	 * 
	 */

	private int GOODS_NO;
	private String MEMBER_ID;
	private int REP_NO;
	private String REP_CON;
	private Date REP_DATE;
	private int REP_START;
	
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
	
}
