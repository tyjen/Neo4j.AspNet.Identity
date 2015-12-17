# Neo4j ASP.NET Identity Provider

## How-To
1. Right click your project or solution in Visual Studio and select `manage NuGet packages`
2. Add the package `Neo4j.AspNet.Identity.Owin`
3. Ensure `ApplicationUser` inherits from `NeoUser`
4. Change the constructor signature for `ApplicationUserManager` to the following:
```
public ApplicationUserManager(IdentityFactoryOptions<ApplicationUserManager> options, IUserStore<ApplicationUser> userStore) : base(userStore)
```
5. Move everything from `ApplicationUserManager.Create` into the constructor and remove the `Create` method.

### Autofac Registration
To tell ASP.NET to use the `NeoUserStore` register the following services:
```
IGraphClient graphClient = new GraphClient(new Uri(Settings.Neo4jUrl), Settings.Neo4jUsername, Settings.Neo4jPassword);
builder.RegisterInstance(graphClient).As<IGraphClient>().SingleInstance();

builder.RegisterType<NeoUserStore<ApplicationUser>>().As<IUserStore<ApplicationUser>>();
builder.Register<IdentityFactoryOptions<ApplicationUserManager>>(c => new IdentityFactoryOptions<ApplicationUserManager>()
{
    DataProtectionProvider = new Microsoft.Owin.Security.DataProtection.DpapiDataProtectionProvider(Strings.ApplicationTitle)
});

builder.Register(c => HttpContext.Current.GetOwinContext().Authentication).As<IAuthenticationManager>();

builder.RegisterType<ApplicationUserManager>().AsSelf().InstancePerRequest();
builder.RegisterType<ApplicationSignInManager>().AsSelf().InstancePerRequest();
```
