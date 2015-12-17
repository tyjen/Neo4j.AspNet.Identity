namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using Microsoft.AspNet.Identity;

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
        public virtual List<NeoUserClaim> Claims { get; private set; }

        /// <summary>
        /// Unique key for the user.
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// Gets the user's login info.
        /// </summary>
        public virtual List<UserLoginInfo> Logins { get; private set; }

        /// <summary>
        /// Gets or sets the password hash.
        /// </summary>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        /// Gets the roles the user belongs to.
        /// </summary>
        public virtual List<string> Roles { get; private set; }

        /// <summary>
        /// Gets or sets the security stamp.
        /// </summary>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        /// Gets or sets the name of the user.
        /// </summary>
        public virtual string UserName { get; set; }

        /// <summary>
        /// Gets or sets the user's email.
        /// </summary>
        public virtual string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's phone.
        /// </summary>
        public virtual string Phone { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this user's phone number is confirmed.
        /// </summary>
        /// <value>
        /// <c>true</c> if phone confirmed; otherwise, <c>false</c>.
        /// </value>
        public virtual bool IsPhoneConfirmed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this user's email is confirmed.
        /// </summary>
        /// <value>
        /// <c>true</c> if email confirmed; otherwise, <c>false</c>.
        /// </value>
        public virtual bool IsEmailConfirmed { get; set; }
    }
}