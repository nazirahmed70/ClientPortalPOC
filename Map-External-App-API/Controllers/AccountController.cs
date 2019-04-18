using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace JWT.Controllers
{

    [Route("api/[controller]")]
    public class AccountController : Controller
    {
        private IConfiguration _config;

        public AccountController(IConfiguration config)
        {
            _config = config;
        }
        [HttpGet]
        public ActionResult<string> Get(string username)
        {

            return getSession(username);
            // return new string[] { "value1", "value2" };
        }

        [AllowAnonymous]
        [HttpPost]

        public IActionResult Login([FromBody]LoginModel login)
        {
            // getSession();
            IActionResult response = Unauthorized();
            var user = Authenticate(login);

            if (user != null)
            {
                var tokenString = BuildToken(user);
                var sessionId = getSession(login.Username);
                response = Ok(new { token = tokenString, SessionId = sessionId });
            }

            return response;
        }

        private string BuildToken(UserModel user)
        {

            var claims = new[] {
        new Claim(JwtRegisteredClaimNames.Sub, user.Name),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim(JwtRegisteredClaimNames.Birthdate, user.Birthdate.ToString("yyyy-MM-dd")),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],

              _config["Jwt:Issuer"],
              claims,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel Authenticate(LoginModel login)
        {
            UserModel user = null;
            //var connectionString = "";
            //using (SqlConnection sql = new SqlConnection(connectionString))
            //{

            //    try
            //    {
            //        SqlCommand command = new SqlCommand("usp_getUserInfo", sql);
            //        command.Parameters.AddWithValue("@username", login.Username);
            //        command.Parameters.AddWithValue("@password", login.Password);
            //        command.CommandType = CommandType.StoredProcedure;
            //        using (SqlDataReader reader = command.ExecuteReader())
            //        {

            //            if (reader.Read())
            //            {
            //                user = new UserModel()
            //                {
            //                    Name = reader["Name"].ToString(),
            //                    Email = reader["Email"].ToString()

            //                };
            //            }
            //        }
            //    }
            //    catch (Exception ex)
            //    {

            //    }

            //}



            if (login.Username == "sa_transre" && login.Password == "12345")
            {
                user = new UserModel { Name = "Sa", Email = "abc@xyz.com" };
            }
            return user;
        }





        public string getSession(string username)
        {

            string Username = username;
            string password = "12345";


            String url = "http://lhrlt-1844/MicroStrategy/asp/TaskAdmin.aspx?taskId=getSessionState&taskEnv=xml&taskContentType=xml&server=localhost&project=MicroStrategy+Tutorial&uid=" + Username + "&pwd=" + password + "";
            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(url);
            request.Method = "GET";
            request.UseDefaultCredentials = true;
            request.PreAuthenticate = true;
            request.Credentials = new NetworkCredential("Administrator", "", "systemsltd.local");
            // username and password are information about and Windows account, so you have to insert

            HttpWebResponse response;
            Stream stream;
            StreamReader streamReader;

            response = (HttpWebResponse)request.GetResponse();
            stream = response.GetResponseStream();
            streamReader = new StreamReader(stream);

            string stringXml = streamReader.ReadToEnd();
            String[] str = new string[] { "<min-state>", "</min-state>" };

            string[] mstrSession = stringXml.Split(str, 3, StringSplitOptions.None);


            return mstrSession[1];
            //  string url2 = "https://localhost/MicroStrategy/asp/Main.aspx?evt=2048001&src=Main.aspx.2048001&visMode=0&currentViewMedia=2&documentID=8AF8FCJHDY1234125CD&server=server1&Project=tutorial&port=0&share=1&hiddensections=header,path,dockTop,dockLeft,footer&usrSmgr=" + mstrSession[1];



        }

        public class LoginModel
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        private class UserModel
        {
            public string Name { get; set; }
            public string Email { get; set; }
            public DateTime Birthdate { get; set; }
        }
    }
}