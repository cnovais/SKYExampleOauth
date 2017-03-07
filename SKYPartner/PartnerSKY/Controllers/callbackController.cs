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
            var chavePrivadaQueReconstruiraAAssinatura = "d3cf64a3-9ce9-4683-bd6d-7513cd64f020"; // parametro secret do XML entregue
            //var chavePrivadaQueReconstruiraAAssinatura = "473010f4-9789-4d46-b5fa-ecaa590c326c"; // telecine
            
            var urlCallbackPartner = "http://localhost:60183/callback"; // use o método que quiser para obter este valor. coloquei manualmente apenas para facilitar o entendimento
        

            // Os métodos usados na sequência são auto-exlicativos.
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

            /// Ao criar o Base64, um sinal de '+' pode ser adicionado (faz parte da especificação), e ao ser encodado 
            /// para sofrer o redirect, vira %2B (veja http://www.w3schools.com/tags/ref_urlencode.asp).
            /// No C#, ao usar o UrlDecode, ele primeiro interpreta o %2B como sinal de '+' e na sequência, 
            /// interpreta o sinal de '+' como espaço em branco (na especificação  do w3schools, url acima, temos essa informação!
            /// 
            /// Teste exaustivamente sua implementação para  ter certeza de que fará a comparação correta no caso do sinal de + fazer 
            /// parte da assinatura.
            /// Ex.:
            /// Assinatura encodada na URL: oauth_signature=hSOTxjCJAWs%2BGDUx%2B3tAtdSlMHA%3D (note o %2B);
            /// Base64 que foi encodado e colocado na URL: hSOTxjCJAWs+GDUx+3tAtdSlMHA= (veja os dois sinais de '+')
            /// Assinatura desencodada pelo C#: hSOTxjCJAWs GDUx 3tAtdSlMHA= (note os espaços em branco)
            /// 
            /// Avalie se a implementação do PHP tem esse comportamento ou não e tome cuidado para não recusar chaves válidas!
            
            var assinaturaOriginal = HttpUtility.UrlDecode(oauth_signature).Replace(' ', '+');
            ViewBag.original = assinaturaOriginal;
            ViewBag.reconstruida = assinaturaReconstruida;

            var ok = assinaturaReconstruida == assinaturaOriginal;

            /// Uma vez que a assinatura recriada é validada, os dados transferidos no request podem ser aceitos como válidos,
            /// porém, você poderá (eu acho que deve!) também avaliar outros itens de segurança, como por ex.:
            /// 
            /// Nounce: number generated once time - faz parte da assinatura e você pode armazená-lo até que o tempo de validade 
            /// do request expire. Só pode ser usado uma vez e sua utilização evita o ataque replay, que é quando o GET é 
            /// interceptado, ainda é válido, e o hacker tenta usar mais uma vez. Como vc armazenou o nounce, o acesso deve ser 
            /// recusado.
            /// 
            /// Time stamp: utilização óbvia, o request pode ser válido por, por ex., 30 segundos, depois disso, é recusado e 
            /// o nounce pode ser recusado.

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
            // só implementamos duas formas de assinaturas, plain text (que não usamos) e hmac sha1.
            switch (signatureType)
            {
                case SignatureTypes.PLAINTEXT:
                    return this.UrlEncode(string.Format("{0}&{1}", consumerSecret, tokenSecret));
                case SignatureTypes.HMACSHA1:  // esta é a que usamos na SKY
                    // gera a assinatura base
                    var signatureBase = GenerateSignatureBase(url, consumerKey, token, tokenSecret, httpMethod, timeStamp, nonce, HMACSHA1SignatureType, usuarioSKY, nome, email);//, out normalizedUrl, out normalizedRequestParameters);

                    // cria o hmac sha1
                    var hmacsha1 = new HMACSHA1
                    {
                        Key =
                            Encoding.ASCII.GetBytes(string.Format("{0}&{1}",
                                                                  this.UrlEncode(consumerSecret),
                                                                  string.IsNullOrEmpty(tokenSecret)
                                                                      ? ""
                                                                      : this.UrlEncode(tokenSecret)))
                    };

                    // gera a assinatura base64 usando a assinatura base e o hmac
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
            parameters.Add(new QueryParameter(OAuthusUsuarioSKY, usuarioSKY.ToString())); // Parâmetros extras q devem ser incluídos na assinatura base
            parameters.Add(new QueryParameter(OAuthusUsuarioNome, nome)); // Parâmetros extras q devem ser incluídos na assinatura base
            parameters.Add(new QueryParameter(OAuthusUsuarioEmail, email)); // Parâmetros extras q devem ser incluídos na assinatura base

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
            //var hasheada = ComputeHash(hash, signatureBase);
            //var encodada = HttpUtility.UrlEncode(hasheada);
            //return encodada;
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
