using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;

namespace SKYPartner.Controllers
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

    public class LoginController : Controller
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

        public ActionResult Index(string id)
        {
            var PartnerKey = "35670e64-db64-4f7b-bf8f-8c4ba7505c3e";

            if (!string.IsNullOrEmpty(id) && id.Trim().Equals(PartnerKey))
            {

                return View();
            }
            else
            {
                throw new HttpException(404, "A página que você procura não existe");

            }
        }

        public ActionResult Entrar(FormCollection form)
        {
          
            if (isUserValid(getUserName(form), getPass(form)))
            {
                var urlNormalizada = string.Empty;
                var paramsDoRequestNormalizados = string.Empty;
                var urlCallbackPartner = "http://localhost:60183/callback";
                var chavePublicaQueIdentificaQueARespostaVeioDaSKY = "d1334118-caba-43ae-9288-16153f856eae";
                var chavePrivadaQueReconstruiraAAssinatura = "d3cf64a3-9ce9-4683-bd6d-7513cd64f020";

                var assinaturaOAuth = this.GenerateSignature(new Uri(urlCallbackPartner), 
                    chavePublicaQueIdentificaQueARespostaVeioDaSKY, 
                    chavePrivadaQueReconstruiraAAssinatura, 
                    "", "", "GET", 
                    this.GenerateTimeStamp(), 
                    this.GenerateNonce(), 
                    SignatureTypes.HMACSHA1, 
                    1234567890, 
                    "Meu Nome", 
                    "meuemail@email.com", 
                    out urlNormalizada, out paramsDoRequestNormalizados);
                    
                var url = string.Format("{0}?{1}&oauth_signature={2}", urlCallbackPartner, paramsDoRequestNormalizados, assinaturaOAuth);

                return Redirect(url);
            }
          
            throw new HttpException("Login inválido");
        }

        private static string getPass(FormCollection form)
        {
            return form[1].ToString();
        }

        private static string getUserName(FormCollection form)
        {
            return form[0].ToString();
        }

        private static bool isUserValid(string username, string pass)
        {
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(pass))
            {
                return System.Configuration.ConfigurationManager.AppSettings["user"].Equals(username) && System.Configuration.ConfigurationManager.AppSettings["pwd"].Equals(pass);
            }

            return false;
        }

        /// <summary>
        /// O processo  começa aqui!
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
        /// <param name="normalizedUrl"></param>
        /// <param name="normalizedRequestParameters"></param>
        /// <returns></returns>
        private string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, SignatureTypes signatureType, long usuarioSKY, string nome, string email, out string normalizedUrl, out string normalizedRequestParameters)
        {
            normalizedUrl = null;
            normalizedRequestParameters = null;

            switch (signatureType)
            {
                case SignatureTypes.PLAINTEXT:
                    return this.UrlEncode(string.Format("{0}&{1}", consumerSecret, tokenSecret));
                case SignatureTypes.HMACSHA1:
                    var signatureBase = GenerateSignatureBase(url, consumerKey, token, tokenSecret, httpMethod, timeStamp, nonce, HMACSHA1SignatureType, usuarioSKY, nome, email, out normalizedUrl, out normalizedRequestParameters);

                    var hmacsha1 = new HMACSHA1
                    {
                        Key =
                            Encoding.ASCII.GetBytes(string.Format("{0}&{1}",
                                                                  this.UrlEncode(consumerSecret),
                                                                  string.IsNullOrEmpty(tokenSecret)
                                                                      ? ""
                                                                      : this.UrlEncode(tokenSecret)))
                    };

                    return GenerateSignatureUsingHash(signatureBase, hmacsha1);
                case SignatureTypes.RSASHA1:
                    throw new NotImplementedException();
                default:
                    throw new ArgumentException("Unknown signature type", "signatureType");
            }
        }

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

        private string GenerateSignatureBase(Uri url, string consumerKey, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, string signatureType, long usuarioSKY, string nome, string email, out string normalizedUrl, out string normalizedRequestParameters)
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
            parameters.Add(new QueryParameter(OAuthusUsuarioSKY, usuarioSKY.ToString())); // parâmetros adicionais
            parameters.Add(new QueryParameter(OAuthusUsuarioNome, nome)); // parâmetros adicionais
            parameters.Add(new QueryParameter(OAuthusUsuarioEmail, email)); // parâmetros adicionais

            parameters.Sort(new QueryParameterComparer());

            normalizedUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
            if (!((url.Scheme == "http" && url.Port == 80) || (url.Scheme == "https" && url.Port == 443)))
            {
                normalizedUrl += ":" + url.Port;
            }
            normalizedUrl += url.AbsolutePath;
            normalizedRequestParameters = NormalizeRequestParameters(parameters);

            var signatureBase = new StringBuilder();
            signatureBase.AppendFormat("{0}&", httpMethod.ToUpper());
            signatureBase.AppendFormat("{0}&", this.UrlEncode(normalizedUrl));
            signatureBase.AppendFormat("{0}", this.UrlEncode(normalizedRequestParameters));

            return signatureBase.ToString();
        }
                
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

        private string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash)
        {
            var hasheada = ComputeHash(hash, signatureBase);
            return HttpUtility.UrlEncode(hasheada);
            //return EncodeMaiusculo(encodada);
        }

        /// <summary>
        /// Opcional, apenas para manter um padrão de encodes maiúsculos na URL, caso necessário.
        /// </summary>
        /// <param name="encodada"></param>
        /// <returns></returns>
        private static string EncodeMaiusculo(string encodada)
        {
            // pra deixar o encoding uppercase
            Regex reg = new Regex(@"%[a-f0-9]{2}");
            return reg.Replace(encodada, m => m.Value.ToUpperInvariant());
        }

        private string GenerateTimeStamp()
        {
            // implementação default da hora UNIX da atual UTC
            var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }

        private string GenerateNonce()
        {
            return new Random().Next(123400, 9999999).ToString();
        }

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
