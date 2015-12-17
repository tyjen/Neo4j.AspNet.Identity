namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Neo4jClient;

    internal class Neo4jHelper
    {
        /// <summary>
        /// The internal client used to talk to Neo4j.
        /// </summary>
        private IGraphClient graphClient { get; set; }

        /// <summary>
        /// The node label the helper works with.
        /// </summary>
        private string nodeType { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Neo4jHelper"/> class.
        /// </summary>
        /// <param name="graphClient">The internal client used to talk to Neo4j.</param>
        /// <param name="nodeType">The node label the helper works with.</param>
        public Neo4jHelper(IGraphClient graphClient, string nodeType)
        {
            if (graphClient == null) throw new ArgumentNullException(nameof(graphClient));
            if (string.IsNullOrWhiteSpace(nodeType)) throw new ArgumentNullException(nameof(nodeType));

            this.graphClient = graphClient;
            this.nodeType = nodeType;
        }

        /// <summary>
        /// Deletes a node by its Id.
        /// </summary>
        public Task DeleteByIdAsync(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) throw new ArgumentNullException(nameof(id));

            return this.graphClient.Cypher
               .Match("(x:" + this.nodeType + ")")
               .Where($"x.Id = '{id}'")
               .Delete("x")
               .ExecuteWithoutResultsAsync();
        }

        /// <summary>
        /// Finds nodes by Id.
        /// </summary>
        public Task<IEnumerable<TNode>> FindByIdAsync<TNode>(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) throw new ArgumentNullException(nameof(id));

            return this.graphClient.Cypher
                    .Match("(x:" + this.nodeType + ")")
                    .Where($"x.Id = '{id}'")
                    .Return(x => x.As<TNode>())
                    .ResultsAsync;
        }

        /// <summary>
        /// Finds a single node by id.
        /// </summary>
        public async Task<TNode> FindOneByIdAsync<TNode>(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) throw new ArgumentNullException(nameof(id));

            IEnumerable<TNode> results = await this.FindByIdAsync<TNode>(id);
            return results.FirstOrDefault();
        }

        /// <summary>
        /// Finds nodes by a property value.
        /// </summary>
        public Task<IEnumerable<TNode>> FindByPropertyAsync<TNode>(string propertyName, string value)
        {
            if (string.IsNullOrWhiteSpace(propertyName)) throw new ArgumentNullException(nameof(propertyName));

            return this.graphClient.Cypher
                    .Match("(x:" + this.nodeType + ")")
                    .Where($"x.{propertyName} = '{value}'")
                    .Return(x => x.As<TNode>())
                    .ResultsAsync;
        }

        /// <summary>
        /// Finds a single node by a property value.
        /// </summary>
        public async Task<TNode> FindOneByPropertyAsync<TNode>(string propertyName, string value)
        {
            if (string.IsNullOrWhiteSpace(propertyName)) throw new ArgumentNullException(nameof(propertyName));

            IEnumerable<TNode> results = await this.FindByPropertyAsync<TNode>(propertyName, value);
            return results.FirstOrDefault();
        }
    }
}
