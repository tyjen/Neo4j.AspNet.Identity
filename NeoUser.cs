namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Newtonsoft.Json;

    /// <summary>
    /// User object for ASP.NET identity.
    /// </summary>
    public class NeoUser : IdentityUser
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUser"/> class.
        /// </summary>
        public NeoUser()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NeoUser"/> class.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public NeoUser(string userName)
            : base(userName)
        {
        }
    }
}