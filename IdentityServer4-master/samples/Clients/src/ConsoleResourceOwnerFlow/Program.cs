using Clients;
using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace ConsoleResourceOwnerFlow
{
    public class Program
    {
        static async Task Main()
        {
            Console.Title = "Console ResourceOwner Flow";

            var response = await RequestTokenAsync();
            response.Show();

            Console.ReadLine();
            await CallServiceAsync(response.AccessToken);
        }

        static async Task<TokenResponse> RequestTokenAsync()
        {
            var client = new HttpClient();

            var disco = await client.GetDiscoveryDocumentAsync(Constants.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var response = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint,

                ClientId = "privateClient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "bob",

                Scope = "api1",
            });

            if (response.IsError) throw new Exception(response.Error);
            return response;
        }

        static async Task CallServiceAsync(string token)
        {
            var baseAddress = Constants.SampleApi;

            var client = new HttpClient
            {
                BaseAddress = new Uri(baseAddress)
            };

            client.SetBearerToken(token);
            var response1 = await client.GetStringAsync("identity/public");
            Console.WriteLine(response1);
            
            var response2 = await client.GetStringAsync("identity/private");
            Console.WriteLine(response2);
        }
    }
}