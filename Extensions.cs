namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Internal extension functions.
    /// </summary>
    internal static class Extensions
    {
        /// <summary>
        /// Converts an IEnumberable of T to a IList of T
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="enumerable">The enumerable.</param>
        /// <returns>IList{``0}.</returns>
        internal static IList<T> ToIList<T>(this IEnumerable<T> enumerable)
        {
            return enumerable.ToList();
        }
    }
}