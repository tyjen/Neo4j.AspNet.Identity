namespace Neo4j.AspNet.Identity
{
    using System;
    using Microsoft.AspNet.Identity;
    using Newtonsoft.Json;

    public class NeoLoginInfo
    {
        public const string RelationHasLogin = "HAS_LOGIN";

        public NeoLoginInfo()
        {
        }

        public NeoLoginInfo(UserLoginInfo userLogin)
        {
            this.Key = userLogin.ProviderKey;
            this.Provider = userLogin.LoginProvider;
        }

        [JsonProperty("providerKey")]
        public string Key { get; set; }

        [JsonProperty("provider")]
        public string Provider { get; set; }

        public UserLoginInfo ToLoginInfo()
        {
            return new UserLoginInfo(this.Provider, this.Key);
        }
    }
}