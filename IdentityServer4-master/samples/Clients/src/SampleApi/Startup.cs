using Clients;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;

namespace SampleApi
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddCors();
            services.AddDistributedMemoryCache();

            services.AddAuthentication("token")
                .AddIdentityServerAuthentication("token", options =>
                {
                    options.Authority = Constants.Authority;
                    options.RequireHttpsMetadata = false;

                    // enable for MTLS scenarios
                    // options.Authority = Constants.AuthorityMtls;

                    options.ApiName = "api1";
                    options.ApiSecret = "secret";

                    options.JwtBearerEvents = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
                    {
                        OnTokenValidated = e =>
                        {
                            var jwt = e.SecurityToken as JwtSecurityToken;
                            var type = jwt.Header.Typ;

                            if (!string.Equals(type, "at+jwt", StringComparison.Ordinal))
                            {
                                e.Fail("JWT is not an access token");
                            }

                            return Task.CompletedTask;
                        }
                    };
                })
                .AddCertificate(options =>
                {
                    options.AllowedCertificateTypes = CertificateTypes.All;
                });
            
            // todo: change to Scope
            services.AddAuthorization(options =>
            {
                var policyBuilder = new AuthorizationPolicyBuilder()
                    .RequireClaim(JwtClaimTypes.ClientId)
                    .RequireAuthenticatedUser();

                policyBuilder
                    .Requirements
                    .Add(new ClaimRequirement(new []
                    {
                        new Claim(JwtClaimTypes.ClientId, "privateClient")
                    }));
                
                var policy = policyBuilder.Build();
                options.AddPolicy("PrivatePolicy", policy);
            });
            services.AddSingleton<IAuthorizationHandler, ClaimAuthorizationHandler>();
            
            // enable for MTLS scenarios
            // services.AddCertificateForwarding(options =>
            // {
            //     options.CertificateHeader = "X-SSL-CERT";
            //
            //     options.HeaderConverter = (headerValue) =>
            //     {
            //         X509Certificate2 clientCertificate = null;
            //
            //         if(!string.IsNullOrWhiteSpace(headerValue))
            //         {
            //             byte[] bytes = Encoding.UTF8.GetBytes(Uri.UnescapeDataString(headerValue));
            //             clientCertificate = new X509Certificate2(bytes);
            //         }
            //
            //         return clientCertificate;
            //     };
            // });
        }

        public void Configure(IApplicationBuilder app)
        {
            // enable for MTLS scenarios
            // app.UseForwardedHeaders(new ForwardedHeadersOptions
            // {
            //     ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            // });
            //
            // app.UseCertificateForwarding();
            
            app.UseCors(policy =>
            {
                policy.WithOrigins(
                    "http://localhost:28895",
                    "http://localhost:7017");

                policy.AllowAnyHeader();
                policy.AllowAnyMethod();
                policy.WithExposedHeaders("WWW-Authenticate");
            });

            app.UseRouting();
            app.UseAuthentication();
            
            // enable for MTLS scenarios
            // app.UseMiddleware<ConfirmationValidationMiddleware>(new ConfirmationValidationMiddlewareOptions
            // {
            //     CertificateSchemeName = CertificateAuthenticationDefaults.AuthenticationScheme,
            //     JwtBearerSchemeName = "token"
            // });

            app.UseAuthorization();
            
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
    public class ClaimAuthorizationHandler : AuthorizationHandler<ClaimRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            ClaimRequirement requirement)
        {
            var clients = context
                .User?
                .Claims?
                .Where(c => c.Type == JwtClaimTypes.ClientId)
                .Select(c => c.Value)
                .Distinct();
            
            if (clients != null)
            {
                foreach (var client in clients)
                {
                    if (requirement.Claims.Contains(client))
                    {
                        context.Succeed(requirement);
                        return Task.CompletedTask;
                    }
                }
            }

            context.Fail();
            return Task.CompletedTask;
        }
    }
    
    public class ClaimRequirement : IAuthorizationRequirement
    {
        public ClaimRequirement(Claim[] claims)
        {
            if (claims?.Length > 0)
                Claims = claims
                    .Distinct()
                    .Select(x => x.Value)
                    .ToArray();
        }

        public string[] Claims { get; } = { };
    }
}