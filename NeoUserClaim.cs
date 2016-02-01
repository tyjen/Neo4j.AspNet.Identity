namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Security.Claims;
    using Newtonsoft.Json;

    /// <summary>
    /// Claims for a <see cref="NeoUser"/>.
    /// </summary>
    public class NeoUserClaim
    {
        public const string RelationHasClaim = "HAS_CLAIM";

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserClaim"/> class.
        /// </summary>
        public NeoUserClaim()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUserClaim"/> class.
        /// </summary>
        public NeoUserClaim(Claim claim)
        {
            this.ClaimType = claim.Type;
            this.ClaimValue = claim.Value;
        }

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

        public Claim ToClaim()
        {
            return new Claim(this.ClaimType, this.ClaimValue);
        }
    }
}