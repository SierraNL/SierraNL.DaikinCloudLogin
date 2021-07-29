using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using McMaster.Extensions.CommandLineUtils;

namespace SierraNL.DaikinCloudLogin
{
    public class Program
    {
        private readonly string ClientId = "7rk39602f0ds8lk0h076vvijnb";
        private readonly string Scope = "email+openid+profile";
        private readonly string RedirectUri = "daikinunified://login";
        private readonly string ResponseType = "code";
        private readonly string ApiKey = "3_xRB3jaQ62bVjqXU1omaEsPDVYC0Twi1zfq1zHPu_5HFT0zWkDvZJS97Yw1loJnTm";

        public static int Main(string[] args)
        => CommandLineApplication.Execute<Program>(args);

        [Option(Description = "The username you use in the daikin residential controller")]
        [Required]
        public string Username { get; }

        [Option(Description = "The password you use in the daikin residential controller")]
        [Required]
        public string Password  { get; }
        
        private void OnExecute()
        {
            var daikinCloudLogin = new DaikinCloudLogin();

            var code = daikinCloudLogin.Execute(new Uri("https://daikin-unicloud-prod.auth.eu-west-1.amazoncognito.com/oauth2/authorize"), ClientId, Scope, ResponseType, RedirectUri, ApiKey, Username, Password).GetAwaiter().GetResult();

            Console.WriteLine($"Login succesful for {Username}, retrieved code {code}");
        }
    }
}
