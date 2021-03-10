package com.ezen.Vo;

import java.util.Date;

import org.springframework.web.multipart.MultipartFile;

public class NoticeVO { 

	private int notice_no;
	private String notice_title;
	private String notice_content;
	private Date notice_date;
	private int notice_count;
	private String member_id;
	private MultipartFile uploadFile;
	
	public int getNotice_no()
	{
		return notice_no;
	}

	public void setNotice_no(int notice_no)
	{
		this.notice_no = notice_no;
	}

	public String getNotice_title()
	{
		return notice_title;
	}

	public void setNotice_title(String notice_title)
	{
		this.notice_title = notice_title;
	}

	public String getNotice_content()
	{
		return notice_content;
	}

	public void setNotice_content(String notice_content)
	{
		this.notice_content = notice_content;
	}

	public Date getNotice_date()
	{
		return notice_date;
	}

	public void setNotice_date(Date notice_date)
	{
		this.notice_date = notice_date;
	}

	public int getNotice_count()
	{
		return notice_count;
	}

	public void setNotice_count(int notice_count)
	{
		this.notice_count = notice_count;
	}

	public String getMember_id()
	{
		return member_id;
	}

	public void setMember_id(String member_id)
	{
		this.member_id = member_id;
	}

	public MultipartFile getUploadFile()
	{
		return uploadFile;
	}

	public void setUploadFile(MultipartFile uploadFile)
	{
		this.uploadFile = uploadFile;
	}

	@Override
	public String toString() {
		return "NoticeVO [notice_no=" + notice_no + ", notice_title=" + notice_title + ", notice_content=" + notice_content + ", notice_date="
				+ notice_date + ", notice_count=" + notice_count + ", member_id=" + member_id
				+ ", uploadFile=" + uploadFile + "]";
	}
}
