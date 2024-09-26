# Workshell.SPF

This is a class library for validating SPF records.

## Installation

Stable builds are available as NuGet packages. You can install it via the Package Manager or via the Package Manager Console:

```
Install-Package Workshell.SPF
```

## Usage

You can use the SPF validator like so:

```
var validator = new SPFValidator();
var result = await validator.ValidateAsync("gmail.com", IPAddress.Parse("209.85.161.51")); // There's a sync version too
```

The result is a value from the `SPFResult` enum:

| Value | Meaning | 
| -------- | ------- |
| None | No records were published by the domain or that the domain couldn't be determined |
| Neutral | The domain owner has explicitly stated that he cannot or does not want to assert whether or not the IP address is authorized. |
| Pass | The client is authorized to inject mail with the given identity. |
| Fail | The client is not authorized to use the domain in the given identity. |
| SoftFail | The domain believes the host is not authorized but is not willing to make that strong of a statement. |
| TempError | A temporary error was encountered. |
| PermError | A permenant error was encountered. |

The SPF validator depends on the excellent [DnsClient](https://github.com/MichaCo/DnsClient.NET) for servicing DNS requests. If you use the default constructor in `SPFValidator` then a new instance of `LookupClient` will be created for each instance of the validator.

However, they recommend you create a single instance and share it across all requests. To that end we also have a constructor that takes an `ILookupClient` which can be manually supplied or used with DI.

For example:

```
var lookupClient = new LookupClient();
var validator = new SPFValidator(lookupClient);
```

## MIT License

Copyright (c) Workshell Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.