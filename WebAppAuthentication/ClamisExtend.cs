using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;

namespace WebAppAuthentication
{
    public static class ClamisExtend
    {

        public static UserIdentity ToUserIdentity(this IIdentity identity)
        {
            try
            {
                var clamisList = identity as ClaimsIdentity;
                var dict = new Dictionary<string, string>();
                clamisList.Claims.ToList().ForEach(c =>
                {
                    if (!dict.ContainsKey(c.Type))
                        dict.Add(c.Type.ToLower(), c.Value);
                });
                var userIdentity = new UserIdentity()
                {
                    IsAdmin = Convert.ToBoolean(dict["isadmin"]),
                    Name = dict["name"]?.ToString(),
                    Company = dict["company"]?.ToString(),
                    UserId = dict["userid"]?.ToString()
                };
                return userIdentity;
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}