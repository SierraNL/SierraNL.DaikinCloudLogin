# SierraNL.DaikinCloudLogin

C# console application to follow the authentication flow of the Daikin Residential Controller app, by doing the same calls from code.
The resulting authorization code can be used to automate Daikin airco's that use the cloud-only wifi module.

This is a proof of concept based on a PR (https://github.com/Apollon77/daikin-controller-cloud/pull/17) on the https://github.com/Apollon77/daikin-controller-cloud repo.

And hopefully some inspiration to get https://github.com/openhab/openhab-addons/issues/11032 solved in the Daikin OpenHAB binding.

Example
```
dotnet SierraNL.DaikinCloudLogin.dll --username my@email.com --password mypassword
```

The result will be a line similar to this:
```
Login succesful for my@email.com, retrieved code 7cf2037f-a95f-4242-9a3e-5d8b12d8dc05
```

The UUID/GUID can be used in the OIDC / OAuth2 flow securing the Daikin Cloud API.