package com.ezen.Dao;

import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import com.ezen.Vo.NoticeVO;
import com.ezen.Other.SearchCriteria;


@Repository
public class NoticeDAOImpl implements NoticeDAO
{

	@Inject
	private SqlSession sql;

	private static String namespace = "com.ezen.mappers.noticeMapper";

	@Override
	public void write(NoticeVO vo) throws Exception
	{
		sql.insert(namespace + ".noticeInsert", vo);
	}

	@Override
	public NoticeVO read(int notice_no) throws Exception
	{
		return sql.selectOne(namespace + ".noticeSelect", notice_no);
	}

	@Override
	public void update(NoticeVO vo) throws Exception
	{
		sql.update(namespace + ".noticeUpdate", vo);
	}

	@Override
	public void delete(int notice_no) throws Exception
	{
		sql.delete(namespace + ".noticeDelete", notice_no);
	}
	
	@Override
	public List<NoticeVO> listSearch(SearchCriteria scri) throws Exception
	{
		// TODO Auto-generated method stub
		return sql.selectList(namespace + ".noticeList", scri);
	}

	@Override
	public int countSearch(SearchCriteria scri) throws Exception
	{
		// TODO Auto-generated method stub
		return sql.selectOne(namespace + ".noticecountSearch", scri);
	}

	@Override
	public void insertFile(Map<String, Object> map) throws Exception
	{
		sql.insert(namespace + ".insertFile", map);
	}

	@Override
	public List<Map<String, Object>> selectFileList(int notice_no) throws Exception
	{
		return sql.selectList(namespace + ".selectFileList", notice_no);
	}

	@Override
	public Map<String, Object> selectFileInfo(Map<String, Object> map) throws Exception
	{
		return sql.selectOne(namespace + ".selectFileInfo", map);
	}

	@Override
	public void updateFile(Map<String, Object> map) throws Exception
	{
		sql.update(namespace + ".updateFile", map);
	}
	
	@Override
	public void noticeCount(int notice_no) throws Exception{
		sql.update(namespace +".noticeCount", notice_no);
	}

}
