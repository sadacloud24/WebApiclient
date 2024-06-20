// See https://aka.ms/new-console-template for more information
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

Console.WriteLine("Hello, World!");


string client_id = "61a9eeab-b186-4357-aa53-872ce7b0fff3"; // "a8525082-7b55-47d8-99ec-30cfc4d06c90";
string client_secret = "YZ98Q~oSnFYs9PwgOjYs80kmdlwsQN3wr1XFfdr7"; // "G8q8Q~LCNoEv9vVTam-P3s5kz4ra6K45rJ2x_dl9";
string resource = "api://61a9eeab-b186-4357-aa53-872ce7b0fff3"; // "api://61a9eeab-b186-4357-aa53-872ce7b0fff3";
string authority = "https://login.microsoftonline.com/ed285f83-4f03-4755-ae91-9c7511100a71"; // "https://login.microsoftonline.com/ed285f83-4f03-4755-ae91-9c7511100a71";

string token = GenerateToken();
ClaimsPrincipal claim = ValidateToken();

if (!claim.Identity!.IsAuthenticated)
{
    token = GenerateToken();
    claim = ValidateToken();
}
else
{
    HttpClient client = new HttpClient();
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7002/WeatherForecast");
    request.Content = new StringContent(string.Empty, Encoding.UTF8, "application/json");
    var response = client.SendAsync(request).Result;

    if (response.IsSuccessStatusCode)
    {
        Console.WriteLine(
            response.Content.ReadAsStringAsync().Result);
    }
    else
    {
        Console.WriteLine(response.StatusCode);
    }
}

string GenerateToken()
{
    ClientCredential clientCredential = new ClientCredential(client_id, client_secret);
    AuthenticationContext authContext = new AuthenticationContext(authority);
    return authContext.AcquireTokenAsync(resource, clientCredential, userAss).Result.AccessToken;
}

ClaimsPrincipal ValidateToken()
{
    string myTenant = "ed285f83-4f03-4755-ae91-9c7511100a71";
    var myIssuer = $"https://sts.windows.net/{myTenant}/";
    var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(client_secret));
    var stsDiscoveryEndpoint = String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}/.well-known/openid-configuration", myTenant);
    var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
    var config = configManager.GetConfigurationAsync().Result;

    var tokenHandler = new JwtSecurityTokenHandler();

    var validationParameters = new TokenValidationParameters
    {
        ValidAudience = resource,
        ValidIssuer = myIssuer,
        IssuerSigningKeys = config.SigningKeys,
        ValidateLifetime = false,
        IssuerSigningKey = mySecurityKey
    };

    var validatedToken = (SecurityToken)new JwtSecurityToken();
    var jwtToken = new JwtSecurityTokenHandler();

    return tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
}