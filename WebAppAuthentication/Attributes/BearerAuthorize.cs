using System.Web.Http;
using System.Web.Http.Controllers;

namespace WebAppAuthentication
{
    /// <summary>
    /// Bearer 授权验证
    /// </summary>
    public class BearerAuthorize : AuthorizeAttribute
    {
        /// <summary>
        /// 授权时调用
        /// </summary>
        /// <param name="actionContext"></param>
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }
        /// <summary>
        /// 指示指定的控件是否已获得授权。
        /// </summary>
        /// <param name="actionContext"></param>
        /// <returns></returns>
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            return base.IsAuthorized(actionContext);
        }
        /// <summary>
        /// 处理授权失败的请求
        /// </summary>
        /// <param name="actionContext"></param>
        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            base.HandleUnauthorizedRequest(actionContext);
        }
    }
}