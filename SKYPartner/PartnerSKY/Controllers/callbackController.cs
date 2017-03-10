using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;

namespace PartnerSKY.Controllers
{
    public class QueryParameter
    {
        public QueryParameter(string name, string value)
        {
            Name = name;
            Value = value;
        }

        public string Name { get; private set; }
        public string Value { get; private set; }
    }

    public class QueryParameterComparer : IComparer<QueryParameter>
    {
        #region IComparer<QueryParameter> Members

        public int Compare(QueryParameter x, QueryParameter y)
        {
            return x.Name == y.Name ? string.Compare(x.Value, y.Value) : string.Compare(x.Name, y.Name);
        }

        #endregion
    }

    public class callbackController : Controller
    {

        public enum SignatureTypes
        {
            HMACSHA1,
            PLAINTEXT,
            RSASHA1
        }

        protected const string OAuthVersion = "1.0";
        protected const string OAuthParameterPrefix = "oauth_";
        protected const string OAuthConsumerKeyKey = "oauth_consumer_key";
        protected const string OAuthVersionKey = "oauth_version";
        protected const string OAuthSignatureMethodKey = "oauth_signature_method";
        protected const string OAuthTimestampKey = "oauth_timestamp";
        protected const string OAuthNonceKey = "oauth_nonce";
        protected const string OAuthTokenKey = "oauth_token";
        protected const string OAuthusUsuarioSKY = "uid";
        protected const string OAuthusUsuarioNome = "nome";
        protected const string OAuthusUsuarioEmail = "email";
        protected const string HMACSHA1SignatureType = "HMAC-SHA1";
        protected string UnreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

        public ActionResult Index(string email, string nome, string oauth_consumer_key, string oauth_nonce,
            string oauth_signature_method, string oauth_timestamp, long uid, string oauth_signature)
        {
            var chavePrivadaQueReconstruiraAAssinatura = "d3cf64a3-9ce9-4683-bd6d-7513cd64f020"; // secret parameter parametro secret do XML entregue           
            var urlCallbackPartner = "http://localhost:60183/callback"; // You can use any method you want to get the url value

            var assinaturaReconstruida = this.GenerateSignature(new Uri(urlCallbackPartner),
                        oauth_consumer_key,
                        chavePrivadaQueReconstruiraAAssinatura,
                        "", "", "GET",
                        oauth_timestamp,
                        oauth_nonce,
                        SignatureTypes.HMACSHA1,
                        uid,
                        nome,
                        email);

            /// When creating Base64, a '+' sign can be added (it is part of the specification), and when it is encoded as well
            /// To undergo redirect, turn to% 2B (see http://www.w3schools.com/tags/ref_urlencode.asp).
            /// In C #, when using UrlDecode, it first interprets% 2B as a '+' sign and in sequence,
            /// interprets the '+' sign as white space (in the w3schools specification, url above, we have this info!
            ///
            /// Test your implementation thoroughly to make sure you will make the correct comparison in case of +
            /// part of the signature.
            /// Ex .:
            /// Signature encoded in URL: oauth_signature = hSOTxjCJAWs% 2BGDUx% 2B3tAtdSlMHA% 3D (note% 2B);
            /// Base64 that was encoded and placed in the URL: hSOTxjCJAWs + GDUx + 3tAtdSlMHA = (note the two '+' signs)
            /// Signature uncoded by C#: hSOTxjCJAWs GDUx 3tAtdSlMHA = (note the blanks space)
            ///
            /// Evaluate whether the PHP implementation has this behavior or not and be careful not to refuse valid keys!

            var assinaturaOriginal = HttpUtility.UrlDecode(oauth_signature).Replace(' ', '+');
            ViewBag.original = assinaturaOriginal;
            ViewBag.reconstruida = assinaturaReconstruida;

            var ok = assinaturaReconstruida == assinaturaOriginal;

            /// Once the recreated signature is validated, the data transferred in the request can be accepted as valid,
            /// however, you can (I think you should!) Also evaluate other security items, such as:
            ///
            /// Nounce: number generated once time - is part of the subscription and you can store it until the expiration time
            /// of the request expire. It can only be used once and its use avoids the replay attack, which is when the GET is
            /// intercepted, is still valid, and the hacker tries to use it again. Since you stored the nounce, access should be
            /// refused.
            ///
            /// Time stamp: obvious usage, the request can be valid for eg 30 seconds, after which it is refused and
            /// nounce can be refused.

            return View(ok);
        }

        /// <summary>
        /// Gera a assinatura que deve ser comparada com a assinatura do request.
        /// </summary>
        /// <param name="url"></param>
        /// <param name="consumerKey"></param>
        /// <param name="consumerSecret"></param>
        /// <param name="token"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="httpMethod"></param>
        /// <param name="timeStamp"></param>
        /// <param name="nonce"></param>
        /// <param name="signatureType"></param>
        /// <param name="usuarioSKY"></param>
        /// <param name="nome"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        private string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, SignatureTypes signatureType, long usuarioSKY, string nome, string email)//, out string normalizedUrl, out string normalizedRequestParameters)
        {
            // We only implemented two forms of signatures, plain text (that we do not use) and hmac sha1.
            switch (signatureType)
            {
                case SignatureTypes.PLAINTEXT:
                    return this.UrlEncode(string.Format("{0}&{1}", consumerSecret, tokenSecret));
                case SignatureTypes.HMACSHA1:  // This is the one we use on SKY
                    // Generates the base signature
                    var signatureBase = GenerateSignatureBase(url, consumerKey, token, tokenSecret, httpMethod, timeStamp, nonce, HMACSHA1SignatureType, usuarioSKY, nome, email);//, out normalizedUrl, out normalizedRequestParameters);

                    // Creates the hmac sha1
                    var hmacsha1 = new HMACSHA1
                    {
                        Key =
                            Encoding.ASCII.GetBytes(string.Format("{0}&{1}",
                                                                  this.UrlEncode(consumerSecret),
                                                                  string.IsNullOrEmpty(tokenSecret)
                                                                      ? ""
                                                                      : this.UrlEncode(tokenSecret)))
                    };

                    // Generates base64 signature using base signature and hmac
                    return GenerateSignatureUsingHash(signatureBase, hmacsha1);
                case SignatureTypes.RSASHA1:
                    throw new NotImplementedException();
                default:
                    throw new ArgumentException("Unknown signature type", "signatureType");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="consumerKey"></param>
        /// <param name="token"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="httpMethod"></param>
        /// <param name="timeStamp"></param>
        /// <param name="nonce"></param>
        /// <param name="signatureType"></param>
        /// <param name="usuarioSKY"></param>
        /// <param name="nome"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        private string GenerateSignatureBase(Uri url, string consumerKey, string token, string tokenSecret,
            string httpMethod, string timeStamp, string nonce, string signatureType, long usuarioSKY,
            string nome, string email)
        {
            if (token == null)
                token = string.Empty;

            if (tokenSecret == null)
                tokenSecret = string.Empty;

            if (string.IsNullOrEmpty(consumerKey))
            {
                throw new ArgumentNullException("consumerKey");
            }

            if (string.IsNullOrEmpty(httpMethod))
            {
                throw new ArgumentNullException("httpMethod");
            }

            if (string.IsNullOrEmpty(signatureType))
            {
                throw new ArgumentNullException("signatureType");
            }

            var parameters = GetQueryParameters(url.Query);
            parameters.Add(new QueryParameter(OAuthVersionKey, OAuthVersion));
            parameters.Add(new QueryParameter(OAuthNonceKey, nonce));
            parameters.Add(new QueryParameter(OAuthTimestampKey, timeStamp));
            parameters.Add(new QueryParameter(OAuthSignatureMethodKey, signatureType));
            parameters.Add(new QueryParameter(OAuthConsumerKeyKey, consumerKey));
            parameters.Add(new QueryParameter(OAuthTokenKey, token));
            parameters.Add(new QueryParameter(OAuthusUsuarioSKY, usuarioSKY.ToString())); // Extra parameters to be included in base subscription
            parameters.Add(new QueryParameter(OAuthusUsuarioNome, nome)); // Extra parameters to be included in base subscription
            parameters.Add(new QueryParameter(OAuthusUsuarioEmail, email)); // Extra parameters to be included in base subscription

            parameters.Sort(new QueryParameterComparer());

            var normalizedUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
            if (!((url.Scheme == "http" && url.Port == 80) || (url.Scheme == "https" && url.Port == 443)))
            {
                normalizedUrl += ":" + url.Port;
            }
            normalizedUrl += url.AbsolutePath;
            var normalizedRequestParameters = NormalizeRequestParameters(parameters);

            var signatureBase = new StringBuilder();
            signatureBase.AppendFormat("{0}&", httpMethod.ToUpper());
            signatureBase.AppendFormat("{0}&", this.UrlEncode(normalizedUrl));
            signatureBase.AppendFormat("{0}", this.UrlEncode(normalizedRequestParameters));

            return signatureBase.ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private List<QueryParameter> GetQueryParameters(string parameters)
        {
            if (parameters.StartsWith("?"))
                parameters = parameters.Remove(0, 1);

            var result = new List<QueryParameter>();

            if (!string.IsNullOrEmpty(parameters))
            {
                var p = parameters.Split('&');
                foreach (var s in p.Where(s => !string.IsNullOrEmpty(s) && !s.StartsWith(OAuthParameterPrefix)))
                {
                    if (s.IndexOf('=') > -1)
                    {
                        var temp = s.Split('=');
                        result.Add(new QueryParameter(temp[0], temp[1]));
                    }
                    else
                    {
                        result.Add(new QueryParameter(s, string.Empty));
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hashAlgorithm"></param>
        /// <param name="dados"></param>
        /// <returns></returns>
        private string ComputeHash(HashAlgorithm hashAlgorithm, string dados)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            if (string.IsNullOrEmpty(dados))
                throw new ArgumentNullException("dados");

            var dataBuffer = Encoding.ASCII.GetBytes(dados);
            var hashBytes = hashAlgorithm.ComputeHash(dataBuffer);

            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signatureBase"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        private string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash)
        {
            return ComputeHash(hash, signatureBase);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private string NormalizeRequestParameters(IList<QueryParameter> parameters)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < parameters.Count; i++)
            {
                var p = parameters[i];
                sb.AppendFormat("{0}={1}", p.Name, p.Value);

                if (i < parameters.Count - 1)
                    sb.Append("&");
            }
            return sb.ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private string UrlEncode(string value)
        {
            var result = new StringBuilder();

            foreach (var symbol in value)
            {
                if (UnreservedChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + String.Format("{0:X2}", (int)symbol));
                }
            }
            return result.ToString();
        }
    }
}
