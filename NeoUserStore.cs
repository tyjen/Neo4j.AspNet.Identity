namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Neo4jClient;

    /// <summary>
    /// User store for ASP.NET identity backed by Neo4j.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public class NeoUserStore<TUser> : IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>, IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>
        where TUser : NeoUser
    {
        /// <summary>
        /// The AspNetUsers node label.
        /// </summary>
        private const string UserNodeLabel = "user";

        /// <summary>
        /// The cypher query to match a user node.
        /// </summary>
        private const string UserNodeMatch = "(u:" + NeoUserStore<TUser>.UserNodeLabel + ")";

        /// <summary>
        /// The graph client used to talk to Neo4j.
        /// </summary>
        private readonly IGraphClient graphClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserStore{TUser}"/> class.
        /// </summary>
        public NeoUserStore()
            : this("DefaultConnection")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserStore{TUser}"/> class.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <param name="username">The database username.</param>
        /// <param name="password">The database password.</param>
        public NeoUserStore(string connectionString, string username = null, string password = null)
        {
            if (string.IsNullOrWhiteSpace(connectionString)) throw new ArgumentNullException(nameof(connectionString));

            if (!connectionString.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                connectionString = ConfigurationManager.ConnectionStrings[connectionString].ConnectionString;
            }

            if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
            {
                this.graphClient = new GraphClient(new Uri(connectionString), username, password);
            }
            else
            {
                this.graphClient = new GraphClient(new Uri(connectionString));
            }

            this.graphClient.Connect();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserStore{TUser}"/> class.
        /// </summary>
        /// <param name="neo4JClient">The neo4j graph client.</param>
        public NeoUserStore(IGraphClient neo4JClient)
        {
            if (neo4JClient == null) throw new ArgumentNullException(nameof(neo4JClient));

            this.graphClient = neo4JClient;
            this.graphClient.Connect();
        }

        /// <inheritdoc />
        public Task AddClaimAsync(TUser user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            if (!user.Claims.Any(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value))
            {
                user.Claims.Add(new NeoUserClaim { ClaimType = claim.Type, ClaimValue = claim.Value });
            }

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey)) user.Logins.Add(login);

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task AddToRoleAsync(TUser user, string role)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            if (!user.Roles.Contains(role, StringComparer.InvariantCultureIgnoreCase)) user.Roles.Add(role);

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task CreateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return
                this.graphClient.Cypher
                    .Merge("(user:" + NeoUserStore<TUser>.UserNodeLabel + " { Id: {id} })")
                    .OnCreate()
                    .Set("user = {newUser}")
                    .WithParams(new { id = user.Id, user })
                    .ExecuteWithoutResultsAsync();
        }

        /// <inheritdoc />
        public Task DeleteAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return this.graphClient.Cypher
                .Match(NeoUserStore<TUser>.UserNodeMatch)
                .Where((TUser u) => u.Id == user.Id)
                .Delete("u")
                .ExecuteWithoutResultsAsync();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            // Do nothing
        }

        /// <inheritdoc />
        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            IEnumerable<TUser> results =
                await
                this.graphClient.Cypher
                    .Match(NeoUserStore<TUser>.UserNodeMatch)
                    .Where($"Logins.LoginProvider = '{login.LoginProvider}', Logins.ProviderKey = '{login.ProviderKey}'")
                    .Return(u => u.As<TUser>())
                    .ResultsAsync;

            return results.FirstOrDefault();
        }

        /// <inheritdoc />
        public async Task<TUser> FindByIdAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentNullException(nameof(userId));

            IEnumerable<TUser> userResults =
                await this.graphClient.Cypher
                    .Match(NeoUserStore<TUser>.UserNodeMatch)
                    .Where((TUser u) => u.Id == userId)
                    .Return(u => u.As<TUser>())
                    .ResultsAsync;

            return userResults.FirstOrDefault();
        }

        /// <inheritdoc />
        public async Task<TUser> FindByNameAsync(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));

            IEnumerable<TUser> userResults =
                await
                this.graphClient.Cypher
                    .Match(NeoUserStore<TUser>.UserNodeMatch)
                    .Where((TUser u) => u.UserName == userName)
                    .Return(u => u.As<TUser>())
                    .ResultsAsync;

            return userResults.FirstOrDefault();
        }

        /// <inheritdoc />
        public Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Logins.ToIList());
        }

        /// <inheritdoc />
        public Task<string> GetPasswordHashAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PasswordHash);
        }

        /// <inheritdoc />
        public Task<IList<string>> GetRolesAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult<IList<string>>(user.Roles);
        }

        /// <inheritdoc />
        public Task<string> GetSecurityStampAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.SecurityStamp);
        }

        /// <inheritdoc />
        public Task<bool> HasPasswordAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }

        /// <inheritdoc />
        public Task<bool> IsInRoleAsync(TUser user, string role)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Roles.Contains(role, StringComparer.InvariantCultureIgnoreCase));
        }

        /// <inheritdoc />
        public Task RemoveClaimAsync(TUser user, Claim claim)
        {
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            user.Claims.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public Task RemoveFromRoleAsync(TUser user, string role)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));

            user.Roles.RemoveAll(r => String.Equals(r, role, StringComparison.InvariantCultureIgnoreCase));

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.Logins.RemoveAll(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public Task UpdateAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            this.graphClient.Cypher
                .Match(NeoUserStore<TUser>.UserNodeMatch)
                .Where((TUser u) => u.Id == user.Id)
                .Set("user = {updatedUser}")
                .WithParam("updatedUser", user)
                .ExecuteWithoutResults();

            return Task.FromResult(user);
        }
    }
}