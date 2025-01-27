
ARG DOTNET_VERSION=9.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build

WORKDIR /src

COPY *.csproj ./
RUN dotnet restore "./Emerald.Api.csproj"

COPY . ./
RUN dotnet publish "./Emerald.Api.csproj" -c Release -o /publish

#
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS runtime

WORKDIR /app
EXPOSE 80

COPY --from=build /publish ./
ENTRYPOINT ["dotnet", "Emerald.Api.dll"]