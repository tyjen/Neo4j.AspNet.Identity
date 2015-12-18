namespace Neo4j.AspNet.Identity
{
    using System;
    using Newtonsoft.Json;

    /// <summary>
    /// Claims for a <see cref="NeoUser"/>.
    /// </summary>
    public class NeoUserClaim
    {
        /// <summary>
        /// Gets or sets the type of the claim.
        /// </summary>
        [JsonProperty("type")]
        public virtual string ClaimType { get; set; }

        /// <summary>
        /// Gets or sets the claim value.
        /// </summary>
        [JsonProperty("value")]
        public virtual string ClaimValue { get; set; }

        /// <summary>
        /// Gets or sets the identifier.
        /// </summary>
        [JsonProperty("id")]
        public virtual string Id { get; set; }
    }
}