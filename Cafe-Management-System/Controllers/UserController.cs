using Cafe_Management_System.Models;
using Microsoft.Ajax.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.IO;
using System.Net.Mail; //For Mailing
using System.Threading.Tasks;
using System.Web;

namespace Cafe_Management_System.Controllers
{
    [RoutePrefix("api/User")]
    public class UserController : ApiController
    {
        CafeEntities db = new CafeEntities();
        Response response = new Response();
        [HttpPost,Route("signup")]
        public HttpResponseMessage SignUp([FromBody] User user)
        {
            try {
                User userobj = db.Users
                    .Where(u => u.email == user.email).FirstOrDefault();
                //Check if the user already exists
                if (userobj == null) {
                    //If there is no entry i.e if the user is signing up for first time
                    user.role = "User";
                    user.status = "false";
                    db.Users.Add(user);
                    db.SaveChanges();
                    return Request.CreateResponse(HttpStatusCode.OK,new {message="Successfully Registered"});
                }
                else
                {
                    return Request.CreateResponse(HttpStatusCode.BadRequest,new {message="Email alreay exists"});
                }
            }
            catch(Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, e);
            }
            
        }
        [HttpPost, Route("login")]
        public HttpResponseMessage Login([FromBody] User user)
        {
            try
            {
                User userObj=db.Users
                    .Where(u=>(u.email== user.email && u.password==user.password)).FirstOrDefault();
                if (userObj != null) {
                    if (userObj.status == "true")
                    {
                        return Request.CreateResponse(HttpStatusCode.OK, new { token = TokenManager.GenerateToken(userObj.email,userObj.role)});
                    }
                    else
                    {
                        return Request.CreateResponse(HttpStatusCode.Unauthorized, new { message = "Wait for admin approval" });
                    }
                }
                else
                {
                    return Request.CreateResponse(HttpStatusCode.BadRequest, new { message = "Incorrect Username or password" });
                }

            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, e);
            }
        }
        [HttpGet,Route("checkToken")]
        [CustomAuthenticationFilter]
        public HttpResponseMessage checkToken()
        {
            return Request.CreateResponse(HttpStatusCode.OK, new { message = "true" });
        }
        [HttpGet, Route("getAllUser")]
        [CustomAuthenticationFilter]
        public HttpResponseMessage GetAllUser()
        {
            try 
            {
                var token = Request.Headers.GetValues("authentication").First();
                TokenClaim tokenClaim=TokenManager.ValidateToken(token);
                if(tokenClaim.Role!="admin")
                {
                    return Request.CreateResponse(HttpStatusCode.Unauthorized);
                }
                var result=db.Users.Select(u=>new {u.id,u.name,u.contactNumber,u.email,u.status,u.role})
                    .Where(x=>(x.role=="user"))
                    .ToList();
                return Request.CreateResponse(HttpStatusCode.OK,result);
            }
            catch(Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, e);
            }
        }
        [HttpPost, Route("updateUserStatus")]
        [CustomAuthenticationFilter]
        public HttpResponseMessage UpdateUserStatus(User user)
        {
            try {
                var token = Request.Headers.GetValues("authorization").First();
                TokenClaim tokenClaim=TokenManager.ValidateToken(token);
                if(tokenClaim.Role != "admin")//Check whether it is admin who is doing the update 
                {//if no then
                    return Request.CreateResponse(HttpStatusCode.Unauthorized);
                }
                //if yes then
                User userObj = db.Users.Find(user.id);//Check if there is any user with following details
                if(userObj==null)
                {//If no such user is present then 
                    response.message = "User id does not Found";
                    return Request.CreateResponse(HttpStatusCode.OK,response);
                }
                //Change the status 
                userObj.status = user.status;
                db.Entry(userObj).State = System.Data.Entity.EntityState.Modified;
                db.SaveChanges();
                response.message = "User Status updated Successfully";
                return Request.CreateResponse(HttpStatusCode.OK, response);
            }
            catch(Exception e) {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, e);
            }
            
        }
        [HttpPost,Route("changePassword")]
        [CustomAuthenticationFilter]
        public HttpResponseMessage ChangePassword(ChangePassword changePassword)
        {
            try {
                var token = Request.Headers.GetValues("authorization").First();
                TokenClaim tokenClaim = TokenManager.ValidateToken(token);
                //Find email and old password
                User userObj = db.Users
                    .Where(x => (x.email == tokenClaim.Email && x.password == changePassword.OldPassword)).FirstOrDefault();
                if (userObj != null)
                {
                    userObj.password = changePassword.NewPassword;
                    db.Entry(userObj).State = System.Data.Entity.EntityState.Modified;
                    db.SaveChanges();
                    response.message = "Password Changed successfully";
                    return Request.CreateResponse(HttpStatusCode.OK, response);
                }
                else
                {
                    response.message = "Incorrect Old Password";
                    return Request.CreateResponse(HttpStatusCode.BadRequest,response);
                }
            }
            catch(Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, e);
            }

        }
    }
}
