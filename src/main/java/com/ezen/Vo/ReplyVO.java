package com.ezen.Vo;

import java.util.Date;

public class ReplyVO {
/*  
    notice_no       	number            not null,
    co_num       		number            not null,
    comments_content   	varchar2(2000)    not null,
    comment_writer    	varchar2(30)      not null,
    comments_date   	date              default sysdate,
*/
	private int notice_no;
	private int co_num;
	private String comments_content;
	private String comment_writer;
	private Date comments_date;
	
	public int getNotice_no() {
		return notice_no;
	}
	public void setNotice_no(int notice_no) {
		this.notice_no = notice_no;
	}
	public int getCo_num() {
		return co_num;
	}
	public void setCo_num(int co_num) {
		this.co_num = co_num;
	}
	public String getComments_content() {
		return comments_content;
	}
	public void setComments_content(String comments_content) {
		this.comments_content = comments_content;
	}
	public String getComment_writer() {
		return comment_writer;
	}
	public void setComment_writer(String comment_writer) {
		this.comment_writer = comment_writer;
	}
	public Date getComments_date() {
		return comments_date;
	}
	public void setComments_date(Date comments_date) {
		this.comments_date = comments_date;
	}
	
}