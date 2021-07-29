using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;

namespace SierraNL.DaikinCloudLogin
{
    public class DaikinCloudLogin
    {
        private Uri _samlServerUri;
        private string _samlContext;
        private string _gigyaVersion;
        private List<string> _cookies = new List<string>();
        private string _loginToken;
        private string _samlResponse;
        private string _relayState;
        private List<string> _csrfStateCookies = new List<string>();

        public async Task<string> Execute(Uri authorizeUri, string clientId, string scope, string responseType, string redirectUri, string apiKey, string username, string password) {
            //Start by triggering the OpenId authentication, which triggers the SAML process
            await GetSamlServerUri(authorizeUri, clientId, scope, responseType, redirectUri);
            await GetSamlContext();

            //the are some gigya scripts involved, we need to fetch some values and store cookies from the response
            _gigyaVersion = await GetGigyaVersion(apiKey);

            var ssoCookies = await GetGigyaCookies(apiKey);
            _cookies.AddRange(ssoCookies);

            //Do the actual logging in, using username and password, the samlcontext and the cookies
            _loginToken = await Login(username, password, apiKey);

            //Now continue to SAML session using the login token
            await Continue(apiKey);

            return await GetAuthorizationCode();
        }

        private async Task GetSamlServerUri(Uri authorizeUri, string clientId, string scope, string responseType, string redirectUri) {
            //Calling the authorize URL triggers the SAML session, and return the url to the login page
            using (var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            using(var httpClient = new HttpClient(handler)) {

                //TODO: state and nonce should be properly generated
                var response = await httpClient.GetAsync($"{authorizeUri}?scope={scope}&response_type={responseType}&redirect_uri={redirectUri}&client_id={clientId}&state=blahblah&nonce=asdf34ad");

                if(response.Headers.Contains("set-cookie")) {
                    var cookies = response.Headers.GetValues("set-cookie");
                    _csrfStateCookies.Add(cookies.ElementAt(1).Split(';')[0]);
                    _csrfStateCookies.Add(cookies.ElementAt(2).Split(';')[0]);
                    _cookies.AddRange(cookies);
                }

                _samlServerUri = response.Headers.Location;
            }
        }

        private async Task GetSamlContext() {

            using (var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            using(var httpClient = new HttpClient(handler)) {
                var response = await httpClient.GetAsync(_samlServerUri);

                var queryString = QueryHelpers.ParseQuery(response.Headers.Location.Query);
                _samlContext = queryString["samlContext"];
            }

        }

        private async Task<string> GetGigyaVersion(string apiKey) {

            using(var httpClient = new HttpClient()) {
                var response = await httpClient.GetStringAsync($"https://cdns.gigya.com/js/gigya.js?apiKey={apiKey}");

                var match = Regex.Match(response, @"(\d+-\d-\d+)");
                if(match.Success) {
                    return match.Value;
                }
                else {
                    return null;
                }
            }
        }

        private async Task<IEnumerable<string>> GetGigyaCookies(string apiKey) {

            using(var httpClient = new HttpClient()) {
                var response = await httpClient.GetAsync($"https://cdc.daikin.eu/accounts.webSdkBootstrap&apiKey={apiKey}&sdk=js_latest&format=json");

                if(response.Headers.Contains("set-cookie")) {
                    return response.Headers.GetValues("set-cookie");
                }
                else {
                    return null;
                }
            }
        }

        private async Task<string> Login(string username, string password, string apiKey)
        {
            string json = null;

            var loginCookies = new List<string>();
            loginCookies.AddRange(_cookies);
            loginCookies.Add("hasGmid=ver4");
            loginCookies.Add($"gig_bootstrap_{apiKey}=cdc_ver4");
            loginCookies.Add("gig_canary_3_QebFXhxEWDc8JhJdBWmvUd1e0AaWJCISbqe4QIHrk_KzNVJFJ4xsJ2UZbl8OIIFY=false");
            loginCookies.Add($"gig_canary_ver_3_QebFXhxEWDc8JhJdBWmvUd1e0AaWJCISbqe4QIHrk_KzNVJFJ4xsJ2UZbl8OIIFY={_gigyaVersion}");
            loginCookies.Add("apiDomain_3_QebFXhxEWDc8JhJdBWmvUd1e0AaWJCISbqe4QIHrk_KzNVJFJ4xsJ2UZbl8OIIFY=cdc.daikin.eu");

            _cookies = loginCookies;

            var loginUri = "https://cdc.daikin.eu/accounts.login";
            var queryString = new Dictionary<string, string>();
            queryString.Add("loginID", username);
            queryString.Add("password", password);
            queryString.Add("sessionExpiration", "31536000");
            queryString.Add("targetEnv", "jssdk");
            queryString.Add("include", "profile,");
            queryString.Add("loginMode", "standard");
            queryString.Add("riskContext", "{\"b0\":7527,\"b2\":4,\"b5\":1");
            queryString.Add("APIKey", apiKey);
            queryString.Add("sdk", "js_latest");
            queryString.Add("authMode", "cookie");
            queryString.Add("pageURL", $"https://my.daikin.eu/content/daikinid-cdc-saml/en/login.html?samlContext={_samlContext}");
            queryString.Add("sdkBuild", "12208");
            queryString.Add("format", "json");

            var message = new HttpRequestMessage(HttpMethod.Post, QueryHelpers.AddQueryString(loginUri, queryString));
            message.Headers.Add("Cookie", string.Join("; ", loginCookies));

            using (var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            using(var httpClient = new HttpClient(handler)) {
                var result = await httpClient.SendAsync(message);

                if(result.StatusCode == HttpStatusCode.OK) {
                    json = await result.Content.ReadAsStringAsync();
                }
            }

            if(!string.IsNullOrEmpty(json)) {
                var jsonDocument = JsonDocument.Parse(json);
                // 0 is no error, so we can expect the result to contain the login_token
                if(jsonDocument.RootElement.GetProperty("errorCode").GetInt32() == 0) {
                    return jsonDocument.RootElement.GetProperty("sessionInfo").GetProperty("login_token").GetString();
                }
            }
                
            Console.WriteLine($"Unexpected response from login: {json}");
            return null;
        }

        private async Task Continue(string apiKey)
        {
            TimeSpan t = DateTime.UtcNow.AddHours(1000) - new DateTime(1970, 1, 1);
            int secondsSinceEpoch = (int)t.TotalSeconds;

            var loginCookies = new List<string>();
            loginCookies.AddRange(_cookies);
            loginCookies.Add($"glt_{apiKey}={_loginToken}");
            loginCookies.Add($"gig_loginToken_3_QebFXhxEWDc8JhJdBWmvUd1e0AaWJCISbqe4QIHrk_KzNVJFJ4xsJ2UZbl8OIIFY={_loginToken}");
            loginCookies.Add($"gig_loginToken_3_QebFXhxEWDc8JhJdBWmvUd1e0AaWJCISbqe4QIHrk_KzNVJFJ4xsJ2UZbl8OIIFY_exp={secondsSinceEpoch}");
            loginCookies.Add($"gig_loginToken_3_QebFXhxEWDc8JhJdBWmvUd1e0AaWJCISbqe4QIHrk_KzNVJFJ4xsJ2UZbl8OIIFY_visited={apiKey}");

            var loginUri = $"https://cdc.daikin.eu/saml/v2.0/{apiKey}/idp/sso/continue";
            var queryString = new Dictionary<string, string>();
            queryString.Add("samlContext", _samlContext);
            queryString.Add("loginToken", _loginToken);
            var message = new HttpRequestMessage(HttpMethod.Get, QueryHelpers.AddQueryString(loginUri, queryString));
            message.Headers.Add("Cookie", string.Join("; ", loginCookies));

            using (var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            using(var httpClient = new HttpClient(handler)) {
                var result = await httpClient.SendAsync(message);

                if(result.StatusCode == HttpStatusCode.OK) {
                    var response = await result.Content.ReadAsStringAsync();

                    var match = Regex.Match(response, "value=\"([^\"]+=*)");
                    if(match.Success && match.Groups.Count == 2) {
                        _samlResponse = match.Groups[1].Value;
                        var nextMatch = match.NextMatch();
                        if(nextMatch.Success && nextMatch.Groups.Count == 2) {
                            _relayState = nextMatch.Groups[1].Value;
                        }
                        else {
                            Console.WriteLine($"Expected relaystate not found in: {response}");
                        }
                    }
                    else {
                        Console.WriteLine($"Expected samlResponse not found in: {response}");
                    }
                }
            }
        }

        private async Task<string> GetAuthorizationCode()
        {
            var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "SAMLResponse", _samlResponse },
                { "RelayState", _relayState }
            });

            var message = new HttpRequestMessage(HttpMethod.Post, "https://daikin-unicloud-prod.auth.eu-west-1.amazoncognito.com/saml2/idpresponse");
            message.Content = formContent;
            message.Headers.Add("Cookie", string.Join("; ", _csrfStateCookies));

            using (var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            using(var httpClient = new HttpClient(handler)) {
                var response = await httpClient.SendAsync(message);

                var queryString = QueryHelpers.ParseQuery(response.Headers.Location.Query);
                return queryString["code"];
            }                
        }
    }
}