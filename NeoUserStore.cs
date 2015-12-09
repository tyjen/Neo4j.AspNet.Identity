namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Neo4jClient;

    /// <summary>
    /// User store for ASP.NET identity backed by Neo4j.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public class NeoUserStore<TUser> : IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>, IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IUserEmailStore<TUser>, IUserPhoneNumberStore<TUser>
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
        /// Helper class for neo4j.
        /// </summary>
        private readonly Neo4jHelper neo4jHelper;

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserStore{TUser}"/> class.
        /// </summary>
        /// <param name="neo4JClient">The neo4j graph client.</param>
        public NeoUserStore(IGraphClient neo4JClient)
        {
            if (neo4JClient == null) throw new ArgumentNullException(nameof(neo4JClient));

            this.graphClient = neo4JClient;
            this.graphClient.Connect();
            this.neo4jHelper = new Neo4jHelper(this.graphClient, NeoUserStore<TUser>.UserNodeLabel);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            // No-op
        }

        /// <summary>
        /// Gets the user identifier for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose identifier should be retrieved.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the identifier for the specified <paramref name="user"/>.
        /// </returns>
        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Id);
        }

        /// <summary>
        /// Gets the user name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be retrieved.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the name for the specified <paramref name="user"/>.
        /// </returns>
        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.UserName);
        }

        /// <summary>
        /// Sets the given <paramref name="userName"/> for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param><param name="userName">The user name to set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));

            user.UserName = userName;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Gets the normalized user name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose normalized name should be retrieved.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the normalized user name for the specified <paramref name="user"/>.
        /// </returns>
        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedUserName);
        }

        /// <summary>
        /// Sets the given normalized name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param><param name="normalizedName">The normalized name to set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedName)) throw new ArgumentNullException(nameof(normalizedName));

            user.NormalizedUserName = normalizedName;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to create.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the <see cref="T:Microsoft.AspNet.Identity.IdentityResult"/> of the creation operation.
        /// </returns>
        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            await this.graphClient.Cypher
                    .Merge("(user:" + NeoUserStore<TUser>.UserNodeLabel + " { Id: {id} })")
                    .OnCreate()
                    .Set("user = {newUser}")
                    .WithParams(new { id = user.Id, user })
                    .ExecuteWithoutResultsAsync();

            return IdentityResult.Success;
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to update.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the <see cref="T:Microsoft.AspNet.Identity.IdentityResult"/> of the update operation.
        /// </returns>
        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            await this.graphClient.Cypher
                .Match(NeoUserStore<TUser>.UserNodeMatch)
                .Where((TUser u) => u.Id == user.Id)
                .Set("user = {updatedUser}")
                .WithParam("updatedUser", user)
                .ExecuteWithoutResultsAsync();

            return IdentityResult.Success;
        }

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the <see cref="T:Microsoft.AspNet.Identity.IdentityResult"/> of the update operation.
        /// </returns>
        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            await this.neo4jHelper.DeleteByIdAsync(user.Id);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userID"/> if it exists.
        /// </returns>
        public Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentNullException(nameof(userId));

            return this.neo4jHelper.FindOneByIdAsync<TUser>(userId);
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified normalized user name.
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userID"/> if it exists.
        /// </returns>
        public Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(normalizedUserName)) throw new ArgumentNullException(nameof(normalizedUserName));

            return this.neo4jHelper.FindOneByPropertyAsync<TUser>("UserName", normalizedUserName);
        }

        /// <summary>
        /// Adds an external <see cref="T:Microsoft.AspNet.Identity.UserLoginInfo"/> to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the login to.</param><param name="login">The external <see cref="T:Microsoft.AspNet.Identity.UserLoginInfo"/> to add to the specified <paramref name="user"/>.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (login == null) throw new ArgumentNullException(nameof(login));

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(new IdentityUserLogin<string>
                    {
                        LoginProvider = login.LoginProvider,
                        ProviderKey = login.ProviderKey,
                        ProviderDisplayName = login.ProviderDisplayName,
                        UserId = user.Id
                    });
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Attempts to remove the provided login information from the specified <paramref name="user"/>.
        ///             and returns a flag indicating whether the removal succeed or not.
        /// </summary>
        /// <param name="user">The user to remove the login information from.</param><param name="loginProvider">The login provide whose information should be removed.</param><param name="providerKey">The key given by the external login provider for the specified user.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that contains a flag the result of the asynchronous removing operation. The flag will be true if
        ///             the login information was existed and removed, otherwise false.
        /// </returns>
        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(loginProvider)) throw new ArgumentNullException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey)) throw new ArgumentNullException(nameof(providerKey));

            List<IdentityUserLogin<string>> loginsToKeep = user.Logins.Where(x => !(x.LoginProvider == loginProvider && x.ProviderKey == providerKey)).ToList();
            user.Logins.Clear();

            foreach (IdentityUserLogin<string> userLogin in loginsToKeep)
            {
                user.Logins.Add(userLogin);
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Retrieves the associated logins for the specified <param ref="user"/>.
        /// </summary>
        /// <param name="user">The user whose associated logins to retrieve.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> for the asynchronous operation, containing a list of <see cref="T:Microsoft.AspNet.Identity.UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName)).ToIList());
        }

        /// <summary>
        /// Retrieves the user associated with the specified login provider and login provider key..
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param><param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(loginProvider)) throw new ArgumentNullException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey)) throw new ArgumentNullException(nameof(providerKey));

            IEnumerable<TUser> results =
                await this.graphClient.Cypher
                    .Match(NeoUserStore<TUser>.UserNodeMatch)
                    .Where($"Logins.LoginProvider = '{loginProvider}', Logins.ProviderKey = '{providerKey}'")
                    .Return(u => u.As<TUser>())
                    .ResultsAsync;

            return results.FirstOrDefault();
        }

        /// <summary>
        /// Gets a list of <see cref="T:System.Security.Claims.Claim"/>s to be belonging to the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The role whose claims to retrieve.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1"/> that represents the result of the asynchronous query, a list of <see cref="T:System.Security.Claims.Claim"/>s.
        /// </returns>
        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Claims?.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToIList());
        }

        /// <summary>
        /// Returns a list of users who contain the specified <see cref="T:System.Security.Claims.Claim"/>.
        /// </summary>
        /// <param name="claim">The claim to look for.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task`1"/> that represents the result of the asynchronous query, a list of <typeparamref name="TUser"/> who
        ///             contain the specified claim.
        /// </returns>
        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            IEnumerable<TUser> results =
             await this.graphClient.Cypher
                 .Match(NeoUserStore<TUser>.UserNodeMatch)
                 .Where($"Claims.ClaimType= '{claim.Type}', Claims.ClaimValue = '{claim.Value}'")
                 .Return(u => u.As<TUser>())
                 .ResultsAsync;

            return results?.ToIList();
        }

        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param><param name="claims">A collection of <see cref="T:System.Security.Claims.Claim"/>s to remove.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            List<IdentityUserClaim<string>> userClaims = new List<IdentityUserClaim<string>>(user.Claims);
            userClaims.RemoveAll(x => claims.Any(y => y.Type == x.ClaimType && y.Value == x.ClaimValue));

            user.Claims.Clear();
            foreach (IdentityUserClaim<string> claim in userClaims)
            {
                user.Claims.Add(claim);
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param><param name="claim">The claim to replace.</param><param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claim == null) throw new ArgumentNullException(nameof(claim));
            if (newClaim == null) throw new ArgumentNullException(nameof(newClaim));

            await this.RemoveClaimsAsync(user, new[] { claim }, cancellationToken);
            await this.AddClaimsAsync(user, new[] { newClaim }, cancellationToken);
        }

        /// <summary>
        /// Add claims to a user as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param><param name="claims">The collection of <see cref="T:System.Security.Claims.Claim"/>s to add.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            foreach (Claim claim in claims)
            {
                user.Claims.Add(new IdentityUserClaim<string> { ClaimType = claim.Type, ClaimValue = claim.Value, UserId = user.Id });
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Add a the specified <paramref name="user"/> to the named role.
        /// </summary>
        /// <param name="user">The user to add to the named role.</param><param name="roleName">The name of the role to add the user to.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException(nameof(roleName));
            
            user.Roles.Add(new IdentityUserRole<string> { RoleId = roleName, UserId = user.Id });

            return Task.FromResult(user);
        }

        /// <summary>
        /// Add a the specified <paramref name="user"/> from the named role.
        /// </summary>
        /// <param name="user">The user to remove the named role from.</param><param name="roleName">The name of the role to remove.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException(nameof(roleName));

            IdentityUserRole<string> roleToRemove = user.Roles.FirstOrDefault(x => x.RoleId == roleName);
            if (roleToRemove != null)
            {
                user.Roles.Remove(roleToRemove);
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Gets a list of role names the specified <paramref name="user"/> belongs to.
        /// </summary>
        /// <param name="user">The user whose role names to retrieve.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing a list of role names.
        /// </returns>
        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.Roles?.Select(r => r.RoleId).ToIList());
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/> is a member of the give named role.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param><param name="roleName">The name of the role to be checked.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified <see cref="!:user"/> is
        ///             a member of the named role.
        /// </returns>
        public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException(nameof(roleName));
            return Task.FromResult(user.Roles.Any(r => r.RoleId == roleName));
        }

        /// <summary>
        /// Returns a list of Users who are members of the named role.
        /// </summary>
        /// <param name="roleName">The name of the role whose membership should be returned.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing a list of users who are in the named role.
        /// </returns>
        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName)) throw new ArgumentNullException(nameof(roleName));
            
            IEnumerable<TUser> results = await this.neo4jHelper.FindByPropertyAsync<TUser>("Roles.RoleId", roleName);
            return results?.ToIList();
        }

        /// <summary>
        /// Sets the password hash for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose password hash to set.</param><param name="passwordHash">The password hash to set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            user.PasswordHash = passwordHash;

            return Task.FromResult(user);
        }

        /// <summary>
        /// Gets the password hash for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose password hash to retrieve.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, returning the password hash for the specified <paramref name="user"/>.
        /// </returns>
        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.PasswordHash);
        }

        /// <summary>
        /// Gets a flag indicating whether the specified <paramref name="user"/> has a password.
        /// </summary>
        /// <param name="user">The user to return a flag for, indicating whether they have a password or not.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a password
        ///             otherwise false.
        /// </returns>
        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }

        /// <summary>
        /// Sets the provided security <paramref name="stamp"/> for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param><param name="stamp">The security stamp to set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            user.SecurityStamp = stamp;

            return Task.FromResult(user);
        }

        /// <summary>
        /// Get the security stamp for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.
        /// </returns>
        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.SecurityStamp);
        }

        /// <summary>
        /// Sets the <paramref name="email"/> address for a <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be set.</param><param name="email">The email to set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            user.Email = email;

            return Task.FromResult(user);
        }

        /// <summary>
        /// Gets the email address for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be returned.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous operation, the email address for the specified <paramref name="user"/>.
        /// </returns>
        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.Email);
        }

        /// <summary>
        /// Gets a flag indicating whether the email address for the specified <paramref name="user"/> has been verified, true if the email address is verified otherwise
        ///             false.
        /// </summary>
        /// <param name="user">The user whose email confirmation status should be returned.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous operation, a flag indicating whether the email address for the specified <paramref name="user"/>
        ///             has been confirmed or not.
        /// </returns>
        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.EmailConfirmed);
        }

        /// <summary>
        /// Sets the flag indicating whether the specified <paramref name="user"/>'s email address has been confirmed or not.
        /// </summary>
        /// <param name="user">The user whose email confirmation status should be set.</param><param name="confirmed">A flag indicating if the email address has been confirmed, true if the address is confirmed otherwise false.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            user.EmailConfirmed = confirmed;

            return Task.FromResult(user);
        }

        /// <summary>
        /// Gets the user, if any, associated with the specified, normalized email address.
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        public Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(normalizedEmail)) throw new ArgumentNullException(nameof(normalizedEmail));
            return this.neo4jHelper.FindOneByPropertyAsync<TUser>("Email", normalizedEmail);
        }

        /// <summary>
        /// Returns the normalized email for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email address to retrieve.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the normalized email address if any associated with the specified user.
        /// </returns>
        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.NormalizedEmail);
        }

        /// <summary>
        /// Sets the normalized email for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email address to set.</param><param name="normalizedEmail">The normalized email to set for the specified <paramref name="user"/>.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object representing the asynchronous operation.
        /// </returns>
        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedEmail)) throw new ArgumentNullException(nameof(normalizedEmail));
            user.NormalizedEmail = normalizedEmail;

            return Task.FromResult(user);
        }

        /// <summary>
        /// Sets the telephone number for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose telephone number should be set.</param><param name="phoneNumber">The telephone number to set.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(phoneNumber)) throw new ArgumentNullException(nameof(phoneNumber));
            user.PhoneNumber = phoneNumber;

            return Task.FromResult(user);
        }

        /// <summary>
        /// Gets the telephone number, if any, for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose telephone number should be retrieved.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, containing the user's telephone number, if any.
        /// </returns>
        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>
        /// Gets a flag indicating whether the specified <paramref name="user"/>'s telephone number has been confirmed.
        /// </summary>
        /// <param name="user">The user to return a flag for, indicating whether their telephone number is confirmed.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a confirmed
        ///             telephone number otherwise false.
        /// </returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        /// Sets a flag indicating if the specified <paramref name="user"/>'s phone number has been confirmed..
        /// </summary>
        /// <param name="user">The user whose telephone number confirmation status should be set.</param><param name="confirmed">A flag indicating whether the user's telephone number has been confirmed.</param><param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task"/> that represents the asynchronous operation.
        /// </returns>
        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));
            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(user);
        }
    }
}