package com.ezen.Service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

import org.springframework.stereotype.Service;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@Service

public class KakaoService {


        public String getAccessToken (String authorize_code) {
            String access_Token = "";
            String refresh_Token = "";
            String reqURL = "https://kauth.kakao.com/oauth/token";

            try {
                URL url = new URL(reqURL);

                HttpURLConnection conn = (HttpURLConnection) url.openConnection();

                //    POST �슂泥��쓣 �쐞�빐 湲곕낯媛믪씠 false�씤 setDoOutput�쓣 true濡�

                conn.setRequestMethod("POST");
                conn.setDoOutput(true);

                //    POST �슂泥��뿉 �븘�슂濡� �슂援ы븯�뒗 �뙆�씪誘명꽣 �뒪�듃由쇱쓣 �넻�빐 �쟾�넚
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));
                StringBuilder sb = new StringBuilder();
                sb.append("grant_type=authorization_code");
                sb.append("&client_id=d8575f6840422aad90c30fa099c54912");  //蹂몄씤�씠 諛쒓툒諛쏆� key
                sb.append("&redirect_uri=http://localhost:8085/controller/member/kakaologin");     // 蹂몄씤�씠 �꽕�젙�빐 �넃�� 寃쎈줈
                sb.append("&code=" + authorize_code);
                bw.write(sb.toString());
                bw.flush();

                //    寃곌낵 肄붾뱶媛� 200�씠�씪硫� �꽦怨�
                int responseCode = conn.getResponseCode();
                System.out.println("responseCode : " + responseCode);

                //    �슂泥��쓣 �넻�빐 �뼸�� JSON���엯�쓽 Response 硫붿꽭吏� �씫�뼱�삤湲�
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String line = "";
                String result = "";

                while ((line = br.readLine()) != null) {
                    result += line;
                }
                System.out.println("response body : " + result);

                //    Gson �씪�씠釉뚮윭由ъ뿉 �룷�븿�맂 �겢�옒�뒪濡� JSON�뙆�떛 媛앹껜 �깮�꽦
                JsonParser parser = new JsonParser();
                JsonElement element = parser.parse(result);

                access_Token = element.getAsJsonObject().get("access_token").getAsString();
                refresh_Token = element.getAsJsonObject().get("refresh_token").getAsString();

                System.out.println("access_token : " + access_Token);
                System.out.println("refresh_token : " + refresh_Token);

                br.close();
                bw.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            return access_Token;
        }
        public HashMap<String, Object> getUserInfo (String access_Token) {

            //    �슂泥��븯�뒗 �겢�씪�씠�뼵�듃留덈떎 媛�吏� �젙蹂닿� �떎瑜� �닔 �엳湲곗뿉 HashMap���엯�쑝濡� �꽑�뼵
            HashMap<String, Object> userInfo = new HashMap<String, Object>(); 
            String reqURL = "https://kapi.kakao.com/v2/user/me";
            try {
                URL url = new URL(reqURL);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");

                //    �슂泥��뿉 �븘�슂�븳 Header�뿉 �룷�븿�맆 �궡�슜
                conn.setRequestProperty("Authorization", "Bearer " + access_Token);

                int responseCode = conn.getResponseCode();
                System.out.println("responseCode : " + responseCode);

                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                String line = "";
                String result = "";

                while ((line = br.readLine()) != null) {
                    result += line;
                }
                System.out.println("response body : " + result);

                JsonParser parser = new JsonParser();
                JsonElement element = parser.parse(result);

                JsonObject properties = element.getAsJsonObject().get("properties").getAsJsonObject();
                JsonObject kakao_account = element.getAsJsonObject().get("kakao_account").getAsJsonObject();

                String nickname = properties.getAsJsonObject().get("nickname").getAsString();
                String email = kakao_account.getAsJsonObject().get("email").getAsString();

                userInfo.put("nickname", nickname);
                userInfo.put("email", email);
     

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            return userInfo;
        }
}