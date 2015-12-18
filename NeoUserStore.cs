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
    public class NeoUserStore<TUser> : IUserStore<TUser>, IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>, IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IUserPhoneNumberStore<TUser>, IUserEmailStore<TUser>, IUserLockoutStore<TUser, string>, IUserTwoFactorStore<TUser, string>
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
        /// Helper object for interacting with Neo4j.
        /// </summary>
        private readonly Neo4jHelper neoHelper;

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserStore{TUser}"/> class.
        /// </summary>
        /// <param name="neo4JClient">The neo4j graph client.</param>
        public NeoUserStore(IGraphClient neo4JClient)
        {
            if (neo4JClient == null) throw new ArgumentNullException(nameof(neo4JClient));

            this.graphClient = neo4JClient;
            this.neoHelper = new Neo4jHelper(this.graphClient, NeoUserStore<TUser>.UserNodeLabel);
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

            if (string.IsNullOrWhiteSpace(user.Id))
            {
                // If a user id is not specified, generate a new one.
                user.Id = Guid.NewGuid().ToString("N");
            }

            return
                this.graphClient.Cypher
                    .Merge("(user:" + NeoUserStore<TUser>.UserNodeLabel + " { Id: {id} })")
                    .OnCreate()
                    .Set("user = {newUser}")
                    .WithParams(new { id = user.Id, newUser = user })
                    .ExecuteWithoutResultsAsync();
        }

        /// <inheritdoc />
        public Task DeleteAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return this.neoHelper.DeleteByIdAsync(user.Id);
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
                    .Where($"u.logins.LoginProvider = '{login.LoginProvider}', u.logins.ProviderKey = '{login.ProviderKey}'")
                    .Return(u => u.As<TUser>())
                    .ResultsAsync;

            return results.FirstOrDefault();
        }

        /// <inheritdoc />
        public Task<TUser> FindByIdAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentNullException(nameof(userId));

            return this.neoHelper.FindOneByIdAsync<TUser>(userId);
        }

        /// <inheritdoc />
        public Task<TUser> FindByNameAsync(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));

            return this.neoHelper.FindOneByPropertyAsync<TUser>("username", userName);
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
                .Set("u = {updatedUser}")
                .WithParam("updatedUser", user)
                .ExecuteWithoutResults();

            return Task.FromResult(user);
        }

        /// <summary>
        /// Set the user's phone number
        /// </summary>
        /// <param name="user"/><param name="phoneNumber"/>
        /// <returns/>
        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Get the user phone number
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<string> GetPhoneNumberAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>
        /// Returns true if the user phone number is confirmed
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.IsPhoneConfirmed);
        }

        /// <summary>
        /// Sets whether the user phone number is confirmed
        /// </summary>
        /// <param name="user"/><param name="confirmed"/>
        /// <returns/>
        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.IsPhoneConfirmed = confirmed;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Set the user email
        /// </summary>
        /// <param name="user"/><param name="email"/>
        /// <returns/>
        public Task SetEmailAsync(TUser user, string email)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.Email = email;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Get the user email
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<string> GetEmailAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Email);
        }

        /// <summary>
        /// Returns true if the user email is confirmed
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.IsEmailConfirmed);
        }

        /// <summary>
        /// Sets whether the user email is confirmed
        /// </summary>
        /// <param name="user"/><param name="confirmed"/>
        /// <returns/>
        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.IsEmailConfirmed = confirmed;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Returns the user associated with this email
        /// </summary>
        /// <param name="email"/>
        /// <returns/>
        public Task<TUser> FindByEmailAsync(string email)
        {
            return this.neoHelper.FindOneByPropertyAsync<TUser>("email", email);
        }

        /// <summary>
        /// Returns the DateTimeOffset that represents the end of a user's lockout, any time in the past should be considered
        ///                 not locked out.
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            return Task.FromResult(user.LockoutEndDate.GetValueOrDefault());
        }

        /// <summary>
        /// Locks a user out until the specified end date (set to a past date, to unlock a user)
        /// </summary>
        /// <param name="user"/><param name="lockoutEnd"/>
        /// <returns/>
        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            user.LockoutEndDate = lockoutEnd;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Used to record when an attempt to access the user has failed
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            if (user.LoginAttempts.HasValue)
            {
                user.LoginAttempts++;
            }
            else
            {
                user.LoginAttempts = 1;
            }

            return Task.FromResult(user.LoginAttempts.Value);
        }

        /// <summary>
        /// Used to reset the access failed count, typically after the account is successfully accessed
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task ResetAccessFailedCountAsync(TUser user)
        {
            user.LoginAttempts = null;
            return Task.FromResult(user);
        }

        /// <summary>
        /// Returns the current number of failed access attempts.  This number usually will be reset whenever the password is
        ///                 verified or the account is locked out.
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<int> GetAccessFailedCountAsync(TUser user)
        {
            return Task.FromResult(user.LoginAttempts.GetValueOrDefault(0));
        }

        /// <summary>
        /// Returns whether the user can be locked out.
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            return Task.FromResult(user.IsLockoutEnabled.HasValue && user.IsLockoutEnabled.Value);
        }

        /// <summary>
        /// Sets whether the user can be locked out.
        /// </summary>
        /// <param name="user"/><param name="enabled"/>
        /// <returns/>
        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            if (enabled)
            {
                user.IsLockoutEnabled = true;
            }
            else
            {
                user.IsLockoutEnabled = null;
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Sets whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"/><param name="enabled"/>
        /// <returns/>
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            if (enabled)
            {
                user.IsTwoFactorAuthEnabled = true;
            }
            else
            {
                user.IsTwoFactorAuthEnabled = null;
            }

            return Task.FromResult(user);
        }

        /// <summary>
        /// Returns whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"/>
        /// <returns/>
        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            return Task.FromResult(user.IsTwoFactorAuthEnabled.HasValue && user.IsTwoFactorAuthEnabled.Value);
        }
    }
}