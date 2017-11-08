using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace TkuIpcAuth {
    public abstract class AuthInfo {
        protected HttpContextBase context;        
        protected AuthStor stor;

        private void init(HttpContextBase context, AuthStor stor) {             
            this.stor    = stor;
            this.context = context;            
        }

        public AuthInfo(HttpContext context, AuthStor stor) {            
            init(new HttpContextWrapper(context), stor);
        }

        public AuthInfo(HttpContextBase context, AuthStor stor) {
            init(context, stor);
        }

        /// <summary>
        /// DEC 加密法 - design By Phoenix 2008 - 
        /// </summary>
        /// <param name="pToEncrypt">加密的字串</param> 
        /// <param name="sKey">加密金鑰</param> 
        /// <param name="sIV">初始化向量</param> 
        /// <returns></returns>
        public virtual string Encrypt(string pToEncrypt, string sKey, string sIV) { 
            StringBuilder ret = new StringBuilder(); 
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider()) { 
                //將字元轉換為Byte 
                byte[] inputByteArray = Encoding.Default.GetBytes(pToEncrypt); 
                //設定加密金鑰(轉為Byte) 
                des.Key = ASCIIEncoding.ASCII.GetBytes(sKey); 
                //設定初始化向量(轉為Byte) 
                des.IV = ASCIIEncoding.ASCII.GetBytes(sIV); 
 
                using (MemoryStream ms = new MemoryStream()) { 
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write)) { 
                        cs.Write(inputByteArray, 0, inputByteArray.Length); 
                        cs.FlushFinalBlock(); 
                    } 

                    //輸出資料 
                    foreach (byte b in ms.ToArray()) { 
                        ret.AppendFormat("{0:X2}", b); 
                    }                        
                } 
            } 
            //回傳
            return ret.ToString();         
        }

        /// <summary>
        /// DEC 解密法 - design By Phoenix 2008 - 
        /// </summary>
        /// <param name="pToDecrypt">解密的字串</param> 
        /// <param name="sKey">加密金鑰</param> 
        /// <param name="sIV">初始化向量</param> 
        /// <returns></returns>
        public virtual string Decrypt(string pToDecrypt, string sKey, string sIV) {
            string result = string.Empty;

            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider()) {
                byte[] inputByteArray = new byte[pToDecrypt.Length / 2]; 
                //反轉 
                for (int x = 0; x < pToDecrypt.Length / 2; x++) { 
                    int i = (Convert.ToInt32(pToDecrypt.Substring(x * 2, 2), 16)); 
                    inputByteArray[x] = (byte)i; 
                } 

                //設定加密金鑰(轉為Byte) 
                des.Key = ASCIIEncoding.ASCII.GetBytes(sKey); 
                //設定初始化向量(轉為Byte) 
                des.IV = ASCIIEncoding.ASCII.GetBytes(sIV); 
                
                using (MemoryStream ms = new MemoryStream()) { 
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write)) { 
                        //例外處理 
                        try { 
                            cs.Write(inputByteArray, 0, inputByteArray.Length); 
                            cs.FlushFinalBlock(); 
                            
                            //輸出資料 
                            result = Encoding.Default.GetString(ms.ToArray()); 
                        } 
                        catch (CryptographicException) { 
                            //若金鑰或向量錯誤，傳回N/A 
                            //return "N/A";                            
                        } 
                    } 
                } 
            }

            return result;
        }

        public abstract string GetUserID();
        public abstract bool IsAuthenticated();

        public abstract string RedirectToLoginUrl();
        public abstract void SignIn(string userID);
        public abstract void SignOut();
    }
}
