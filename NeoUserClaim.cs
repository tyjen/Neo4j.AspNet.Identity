namespace Neo4j.AspNet.Identity
{
    using System;

    /// <summary>
    /// Claims for a <see cref="NeoUser"/>.
    /// </summary>
    public class NeoUserClaim
    {
        /// <summary>
        /// Gets or sets the type of the claim.
        /// </summary>
        public virtual string ClaimType { get; set; }

        /// <summary>
        /// Gets or sets the claim value.
        /// </summary>
        public virtual string ClaimValue { get; set; }

        /// <summary>
        /// Gets or sets the identifier.
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// Gets or sets the user identifier.
        /// </summary>
        public virtual string UserId { get; set; }
    }
}