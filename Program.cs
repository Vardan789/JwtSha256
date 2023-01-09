using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

string payload = string.Empty; //your  request  body

string secretKey = "Dg$bWA7d5jwr1mt1qvw*qhV5WV6n3an3CSkt^GetQuIvkIq2K#";

string token = GenerateToken(payload, secretKey);
bool isValid = ValidateToken(token, secretKey);
Console.WriteLine(isValid);

string GenerateToken(string jsonData, string secretRequestKey)
{
    byte[] key = Encoding.ASCII.GetBytes(secretRequestKey);

    SecurityTokenDescriptor tokenDescriptor = new()
    {
        Issuer = "https://staging.atomconstruct.com",
        Audience = "https://sandbox.bs2bet.com",
        Subject = new ClaimsIdentity(new Claim[]
        {
            new("payload", jsonData)
        }),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature),
        Expires = DateTime.UtcNow.AddHours(6)
    };

    JwtSecurityTokenHandler tokenHandler = new();
    SecurityToken securityToken = tokenHandler.CreateToken(tokenDescriptor);
    string accessToken = tokenHandler.WriteToken(securityToken);

    return accessToken;
}

bool ValidateToken(string accessToken, string secretRequestKey)
{
    byte[] key = Encoding.ASCII.GetBytes(secretRequestKey);

    TokenValidationParameters tokenValidationParameters = new()
    {
        ValidIssuer = "https://staging.atomconstruct.com",
        ValidAudience = "https://sandbox.bs2bet.com",
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateLifetime = true
    };

    JwtSecurityTokenHandler tokenHandler = new();
    try
    {
        tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken? securityToken);

        JwtSecurityToken? jwtSecurityToken = securityToken as JwtSecurityToken;

        return (bool)jwtSecurityToken?.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
    }
    catch (Exception)
    {
        return false;
    }
}