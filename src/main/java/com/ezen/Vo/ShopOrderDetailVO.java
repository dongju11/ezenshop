package com.ezen.Vo;

public class ShopOrderDetailVO {

	
	
	/*
	 * 
	 *  CREATE TABLE SHOP_ORDER_DETAIL (
    ORDER_DETAIL_NO number not null,
    ORDER_ID varchar2(50) not null,
    GOODS_NO number not null,
    CARTSTATUS number not null,
    primary key(ORDER_DETAIL_NO)
);
	 * 
	 */
	
	private int ORDER_DETAIL_NO;
	private String ORDER_ID;
	private int GOODS_NO;
	private int CARTSTATUS;
	public int getORDER_DETAIL_NO() {
		return ORDER_DETAIL_NO;
	}
	public void setORDER_DETAIL_NO(int oRDER_DETAIL_NO) {
		ORDER_DETAIL_NO = oRDER_DETAIL_NO;
	}
	public String getORDER_ID() {
		return ORDER_ID;
	}
	public void setORDER_ID(String oRDER_ID) {
		ORDER_ID = oRDER_ID;
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
	
	
}
