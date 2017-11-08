using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Security;
using TkuIpcAuth;

namespace TkuIpcAuthDemo.Controllers {
    public class AccountController : Controller {
        private AuthInfo authInfo;
        private AuthInfoFactory authInfoFactory;

        private AuthStor authStor;
        private AuthStorFactory authStorFactory;

        private HttpContextBase context;

        string storName = WebConfigurationManager.AppSettings["AUTH_STOR"];
        string ssoUrl   = WebConfigurationManager.AppSettings["SSO_URL"];
        string token    = WebConfigurationManager.AppSettings["SSO_TOKEN_NM"];

        public AccountController() { 
            authInfoFactory = new AuthInfoFactory();
            authStorFactory = new AuthStorFactory();        
        }

        protected override void Initialize(System.Web.Routing.RequestContext requestContext) {
            base.Initialize(requestContext);

            context  = this.HttpContext;
            authStor = authStorFactory.GetAuthStor(context, storName);
            authInfo = authInfoFactory.GetAuthInfo(context, authStor);
        }

        /// <summary>
        /// 根據使用者選定的驗證方式，傳回指定的檢視畫面
        /// </summary>
        /// <param name="authName">驗證名稱</param>
        /// <returns></returns>
        public ActionResult GetAuthView(string authName) {
            ActionResult actionResult = HttpNotFound();
                        
            Session.Clear();
                                    
            switch (authName) { 
                case "forms":
                    authStor.SetAuthMethod("forms");                    
                    actionResult = PartialView("FormForFormsAuth");
                    break;

                case "mix":                    
                    Session[token] = "_" + Guid.NewGuid().ToString().Substring(0, 7);

                    authStor.SetAuthMethod("mix");
                    actionResult = PartialView("FormForMixAuth");
                    break;

                case "portal":                    
                    actionResult = Content(ssoUrl + WebConfigurationManager.AppSettings["SSO_PORTAL"]);
                    break;
            }

            return actionResult;
        }

        public ActionResult Login() {
            return View();
        }
        
        /// <summary>
        ///  forms 驗證完畢後會導向此處
        /// </summary>
        /// <returns></returns>
        [HttpPost]        
        [ValidateAntiForgeryToken]
        public ActionResult Login(string user_id, string password) {
            ActionResult actionResult = null;

            if (user_id == password) {
                authInfo.SignIn(user_id);                
                actionResult = RedirectToAction("Index", "Home");
            }
            else {
                ModelState.AddModelError(string.Empty, "驗證錯誤 - 帳號與密碼必須相同：)");
                actionResult = View();
            }
            
            return actionResult;
        }

        /// <summary>
        ///  mix 驗證完畢後會導向此處
        /// </summary>
        /// <returns></returns>        
        public ActionResult LoginMix(string sKey = "") {
            // 若使用 WebAuthStor, 則此刻不宜執行 authInfo.SignIn(user_id)，因為目前仍於 portal
            string sso_userid = Request.Headers["sso_userid"];

            // 檢查是否需要進行加解密
            if (!string.IsNullOrEmpty(sKey)) {
                string sIV      = Guid.NewGuid().ToString().Substring(0, 8);                  
                string user_id  = authInfo.Encrypt(sso_userid, sKey, sIV);
            
                ViewData["redir"] = WebConfigurationManager.AppSettings["SSO_MIX_DECRY"] + "?uid=" + user_id + "&sIV=" + sIV;
            }
            else { 
                ViewData["redir"] = WebConfigurationManager.AppSettings["SSO_MIX_REDIR"] + "?uid=" + sso_userid;
            }


            return View();
        }

        public ActionResult Decrypt(string uID, string sIV) {
            ActionResult actionResult = null;

            string sKey    = Session[token].ToString();
            string user_id = string.Empty; 
            
            try { 
                user_id = authInfo.Decrypt(uID, sKey, sIV);

                authInfo.SignIn(user_id);
                actionResult = RedirectToAction("Index", "Home");
            }
            catch { 
                actionResult = View("Error");
            }
            finally { 
                Session.Remove(token);
            }

            return actionResult;
        }

        /// <summary>
        ///  portal 驗證完畢後會導向此處
        /// </summary>
        /// <returns></returns>
        public ActionResult LoginPortal() {
            authStor.SetAuthMethod("portal");
            return RedirectToAction("Index", "Home");
        }
                
        public ActionResult Logout() {
            string auth = authStor.GetAuthMethod();

            authInfo.SignOut();

            if (auth != "forms") { 
                ViewData["logout"] = ssoUrl + WebConfigurationManager.AppSettings["SSO_LOGOUT"];
            }            

            return View();
        }
    }
}