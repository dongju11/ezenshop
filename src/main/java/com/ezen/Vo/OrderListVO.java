package com.ezen.Vo;

import java.util.Date;

public class OrderListVO {
	
	/*
	 * select
    o.ORDER_ID, o.MEMBER_ID, o.ORDER_REC, o.MEMBER_ADDR, o.ORDER_PHON, o.ORDER_AMOUNT, o.ORDER_DATE,
    d.ORDER_DETAIL_NO, d.GOODS_NO, d.CARTSTATUS,
    g.GOODS_NAME, g.GOODS_THUMBIMG, g.GOODS_PRICE, g.GOODS_DCPRICE
from SHOP_ORDER o
    inner join SHOP_ORDER_DETAIL d
        on o.ORDER_ID = d.ORDER_ID
    inner join GOODS g
        on d.GOODS_NO = g.GOODS_NO
where o.MEMBER_ID = 'EODUD'
    and o.ORDER_ID = '20201229_993619';
	 *  
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
	private int ORDER_DETAIL_NO;
	private int GOODS_NO;
	private int CARTSTATUS;
	
	private String GOODS_NAME;
	private String GOODS_THUMBIMG;
	private int GOODS_PRICE;
	private int GOODS_DCPRICE;
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
	public int getORDER_DETAIL_NO() {
		return ORDER_DETAIL_NO;
	}
	public void setORDER_DETAIL_NO(int oRDER_DETAIL_NO) {
		ORDER_DETAIL_NO = oRDER_DETAIL_NO;
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
	public String getGOODS_NAME() {
		return GOODS_NAME;
	}
	public void setGOODS_NAME(String gOODS_NAME) {
		GOODS_NAME = gOODS_NAME;
	}
	public String getGOODS_THUMBIMG() {
		return GOODS_THUMBIMG;
	}
	public void setGOODS_THUMBIMG(String gOODS_THUMBIMG) {
		GOODS_THUMBIMG = gOODS_THUMBIMG;
	}
	public int getGOODS_PRICE() {
		return GOODS_PRICE;
	}
	public void setGOODS_PRICE(int gOODS_PRICE) {
		GOODS_PRICE = gOODS_PRICE;
	}
	public int getGOODS_DCPRICE() {
		return GOODS_DCPRICE;
	}
	public void setGOODS_DCPRICE(int gOODS_DCPRICE) {
		GOODS_DCPRICE = gOODS_DCPRICE;
	}
	
	
	
	
	
	

}
