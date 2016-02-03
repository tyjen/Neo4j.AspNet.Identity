namespace Neo4j.AspNet.Identity
{
    using System;
    using Microsoft.AspNet.Identity;
    using Newtonsoft.Json;

    /// <summary>
    /// Neo4j model for <see cref="UserLoginInfo"/>.
    /// </summary>
    public class NeoLoginInfo
    {
        /// <summary>
        /// Gets the relationship name for a user who has login info.
        /// </summary>
        public const string RelationHasLogin = "HAS_LOGIN";

        /// <summary>
        /// The login node label.
        /// </summary>
        public const string LoginNodeLabel = "login";

        /// <summary>
        /// The login node cypher match clause.
        /// </summary>
        internal const string LoginNodeMatch = "(l:" + NeoLoginInfo.LoginNodeLabel + ")";

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoLoginInfo"/> class.
        /// </summary>
        public NeoLoginInfo()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoLoginInfo"/> class.
        /// </summary>
        /// <param name="userLogin">The user login to populate from.</param>
        public NeoLoginInfo(UserLoginInfo userLogin)
        {
            this.Key = userLogin.ProviderKey;
            this.Provider = userLogin.LoginProvider;
        }

        /// <summary>
        /// Gets or sets the provider key.
        /// </summary>
        [JsonProperty("providerKey")]
        public string Key { get; set; }

        /// <summary>
        /// Gets or sets the provider name.
        /// </summary>
        [JsonProperty("provider")]
        public string Provider { get; set; }

        /// <summary>
        /// Converts this <see cref="NeoLoginInfo"/> to a <see cref="UserLoginInfo"/>.
        /// </summary>
        public UserLoginInfo ToLoginInfo()
        {
            return new UserLoginInfo(this.Provider, this.Key);
        }
    }
}