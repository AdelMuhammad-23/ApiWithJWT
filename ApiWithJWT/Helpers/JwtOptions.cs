namespace ApiWithJWT.Helpers
{
    public class JwtOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public Double Lifetime { get; set; }
        public string SigningKey { get; set; }
    }

}
