rm *.nupkg
nuget pack Neo4j.AspNet.Identity.csproj -Prop Configuration=Release
nuget push Neo4j.AspNet.Identity.Owin.*.nupkg