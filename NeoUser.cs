namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using Microsoft.AspNet.Identity;
    using Newtonsoft.Json;

    /// <summary>
    /// User object for ASP.NET identity.
    /// </summary>
    public class NeoUser : IUser
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUser"/> class.
        /// </summary>
        public NeoUser()
        {
            this.Claims = new List<NeoUserClaim>();
            this.Roles = new List<string>();
            this.Logins = new List<UserLoginInfo>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUser"/> class.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public NeoUser(string userName)
            : this()
        {
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));

            this.UserName = userName;
        }

        /// <summary>
        /// Gets the user's claims.
        /// </summary>
        [JsonProperty("claims")]
        public virtual List<NeoUserClaim> Claims { get; private set; }

        /// <summary>
        /// Unique key for the user.
        /// </summary>
        [JsonProperty("id")]
        public virtual string Id { get; set; }

        /// <summary>
        /// Gets the user's login info.
        /// </summary>
        [JsonProperty("logins")]
        public virtual List<UserLoginInfo> Logins { get; private set; }

        /// <summary>
        /// Gets or sets the password hash.
        /// </summary>
        [JsonProperty("passwordhash")]
        public virtual string PasswordHash { get; set; }

        /// <summary>
        /// Gets the roles the user belongs to.
        /// </summary>
        [JsonProperty("roles")]
        public virtual List<string> Roles { get; private set; }

        /// <summary>
        /// Gets or sets the security stamp.
        /// </summary>
        [JsonProperty("securitystamp")]
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        /// Gets or sets the name of the user.
        /// </summary>
        [JsonProperty("username")]
        public virtual string UserName { get; set; }

        /// <summary>
        /// Gets or sets the user's email.
        /// </summary>
        [JsonProperty("email")]
        public virtual string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's phone.
        /// </summary>
        [JsonProperty("phonenumber")]
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this user's phone number is confirmed.
        /// </summary>
        [JsonProperty("phoneconfirmed")]
        public virtual bool IsPhoneConfirmed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this user's email is confirmed.
        /// </summary>
        [JsonProperty("emailconfirmed")]
        public virtual bool IsEmailConfirmed { get; set; }

        [JsonProperty("lockoutenddate", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public virtual DateTimeOffset? LockoutEndDate { get; set; }

        [JsonProperty("failedlogins", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public virtual int? LoginAttempts { get; set; }

        [JsonProperty("lockoutenabled", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public virtual bool? IsLockoutEnabled { get; set; }

        [JsonProperty("usetwofactorauth", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public virtual bool? IsTwoFactorAuthEnabled { get; set; }
    }
}