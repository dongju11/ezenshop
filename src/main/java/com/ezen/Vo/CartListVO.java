package com.ezen.Vo;

import java.util.Date;

public class CartListVO {
	/*
	 * private int CART_NO;
	private String MEMBER_ID;
	private int GOODS_NO;
	private int CARTSTATUS;
	private Date ADDDATE;
	 * 
	select
    row_number() over(order by c.CART_NO desc) as num,
    c.CART_NO, c.MEMBER_ID, c.GOODS_NO, c.CARTSTATUS, c.ADDDATE,
    g.GOODS_NAME, g.GOODS_PRICE, g.GOODS_DCPRICE, g.GOODS_BRAND, g.GOODS_SHIPPING, g.GOODS_THUMBIMG
from CART c
    inner join GOODS g
        on c.GOODS_NO = g.GOODS_NO
            where c.MEMBER_ID = 'EODUD';
            
            */
	
	private int CART_NO;
	private String MEMBER_ID;
	private int GOODS_NO;
	private int CARTSTATUS;
	private Date ADDDATE;
	
	private int num;
	private String GOODS_NAME;
	private int GOODS_PRICE;
	private int GOODS_DCPRICE;
	private String GOODS_BRAND;
	private int GOODS_SHIPPING;
	private String GOODS_THUMBIMG;
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
	public int getNum() {
		return num;
	}
	public void setNum(int num) {
		this.num = num;
	}
	public String getGOODS_NAME() {
		return GOODS_NAME;
	}
	public void setGOODS_NAME(String gOODS_NAME) {
		GOODS_NAME = gOODS_NAME;
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
	public String getGOODS_BRAND() {
		return GOODS_BRAND;
	}
	public void setGOODS_BRAND(String gOODS_BRAND) {
		GOODS_BRAND = gOODS_BRAND;
	}
	public int getGOODS_SHIPPING() {
		return GOODS_SHIPPING;
	}
	public void setGOODS_SHIPPING(int gOODS_SHIPPING) {
		GOODS_SHIPPING = gOODS_SHIPPING;
	}
	public String getGOODS_THUMBIMG() {
		return GOODS_THUMBIMG;
	}
	public void setGOODS_THUMBIMG(String gOODS_THUMBIMG) {
		GOODS_THUMBIMG = gOODS_THUMBIMG;
	}

}
