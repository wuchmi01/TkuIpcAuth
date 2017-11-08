using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;

using TkuIpcAuth;

namespace TkuIpcAuthDemo.Controllers {
    [TkuIpcAuthorize]
    public class HomeController : Controller {
        private AuthInfo authInfo;
        private AuthInfoFactory authInfoFactory;

        private AuthStor authStor;
        private AuthStorFactory authStorFactory;

        private HttpContextBase context;

        string storName = WebConfigurationManager.AppSettings["AUTH_STOR"];

        public HomeController() { 
            authInfoFactory = new AuthInfoFactory();
            authStorFactory = new AuthStorFactory();
        }

        protected override void Initialize(System.Web.Routing.RequestContext requestContext) {
            base.Initialize(requestContext);
                        
            context  = this.HttpContext;
            authStor = authStorFactory.GetAuthStor(context, storName);
            authInfo = authInfoFactory.GetAuthInfo(context, authStor);
        }
                
        public ActionResult Index() {
            ViewData["user_id"] = authInfo.GetUserID();
            ViewData["auth"]    = authStor.GetAuthMethod();

            return View();
        }
    }
}