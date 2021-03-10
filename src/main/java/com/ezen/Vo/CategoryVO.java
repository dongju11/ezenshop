package com.ezen.Vo;

/*
 *
CREATE TABLE GOODS_CATEGORY(		
CATENAME VARCHAR2(20) NOT NULL, 		
CATECODE VARCHAR2(30) PRIMARY KEY NOT NULL,		
CATECODEREF VARCHAR2(30) NULL, 		
FOREIGN key(CATECODEREF) REFERENCES GOODS_CATEGORY(CATECODE)	
);		

insert into goods_category (cateName, cateCode) values ('강아지', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('간식/사료', '101', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('위생용품', '102', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('미용용품', '103', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('외출용품', '104', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('안전용품', '105', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('장난감', '106', '100');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('기타', '107', '100');

insert into goods_category (cateName, cateCode) values ('고양이', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('간식/사료', '201', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('위생용품', '202', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('미용용품', '203', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('외출용품', '204', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('안전용품', '205', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('장난감', '206', '200');
insert into goods_category (cateName, cateCode, cateCodeRef) values ('기타', '207', '200');
*/

public class CategoryVO {
	
	private String CATENAME;
	private String CATECODE;
	private String CATECODEREF;
	private int level;
	public int getLevel() {
		return level;
	}
	public void setLevel(int level) {
		this.level = level;
	}
	public String getCATENAME() {
		return CATENAME;
	}
	public void setCATENAME(String cATENAME) {
		CATENAME = cATENAME;
	}
	public String getCATECODE() {
		return CATECODE;
	}
	public void setCATECODE(String cATECODE) {
		CATECODE = cATECODE;
	}
	public String getCATECODEREF() {
		return CATECODEREF;
	}
	public void setCATECODEREF(String cATECODEREF) {
		CATECODEREF = cATECODEREF;
	}
	
	
}
