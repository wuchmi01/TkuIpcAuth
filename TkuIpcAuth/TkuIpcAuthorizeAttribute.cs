using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Security;

namespace TkuIpcAuth {
    public class TkuIpcAuthorizeAttribute : AuthorizeAttribute {
        private AuthInfo authInfo;
        private AuthInfoFactory authInfoFactory;

        private AuthStor authStor;
        private AuthStorFactory authStorFactory;
                            
        public override void OnAuthorization(AuthorizationContext filterContext) {
            var context = filterContext.HttpContext;

            string storName = WebConfigurationManager.AppSettings["AUTH_STOR"];
            
            authStorFactory = new AuthStorFactory();
            authInfoFactory = new AuthInfoFactory();

            authStor = authStorFactory.GetAuthStor(context, storName);
            authInfo = authInfoFactory.GetAuthInfo(context, authStor);

            // AuthorizationCore() will be called by base.OnAuthorization()
            base.OnAuthorization(filterContext);
        }

        protected override bool AuthorizeCore(HttpContextBase httpContext) {
            var isAuth = authInfo.IsAuthenticated();           
            return isAuth;
        }
    }
}