using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using DnsClient;
using NetTools;

namespace Workshell.SPF;

public delegate void SPFServiceErrorEventHandler(object sender, SPFValidatorErrorEventArgs e);

public sealed class SPFValidator
{
    private enum Qualifier
    {
        Pass,
        Neutral,
        SoftFail,
        Fail
    }

    private static readonly IDictionary<char, Qualifier> Qualifiers = new Dictionary<char, Qualifier>()
    {
        { '+', Qualifier.Pass },
        { '?', Qualifier.Neutral },
        { '~', Qualifier.SoftFail },
        { '-', Qualifier.Fail },
    };

    private readonly ILookupClient _dnsClient;

    public SPFValidator()
        : this(new LookupClient())
    {
    }

    public SPFValidator(ILookupClient dnsClient)
    {
        _dnsClient = dnsClient ?? throw new ArgumentNullException(nameof(dnsClient));
    }

    #region Methods

    public SPFResult Validate(string sendersDomain, IPAddress sendersIP)
    {
        return ValidateAsync(sendersDomain, sendersIP, CancellationToken.None)
            .GetAwaiter()
            .GetResult();
    }

    public async Task<SPFResult> ValidateAsync(string sendersDomain, IPAddress sendersIP, CancellationToken cancellationToken = default)
    {
        var records = await GetTXTRecordsAsync(sendersDomain, cancellationToken);

        return await PerformValidationAsync(records, sendersDomain, sendersIP, 0, cancellationToken);
    }

    private async Task<SPFResult> PerformValidationAsync(IReadOnlyCollection<string> records, string sendersDomain, IPAddress sendersIP, int termCount, CancellationToken cancellationToken)
    {
        if (termCount > 10)
        {
            return SPFResult.PermError;
        }

        var results = new List<(string Value, bool Match, Qualifier Qualifier)>();
        var currentTermCount = termCount;
        var redirect = string.Empty;

        foreach (var record in records)
        {
            var verSeen = false;
            var hasAll = false;
            var parts = record.Split(' ');

            foreach (var part in parts)
            {
                var value = part.ToLower();

                if (value.Equals("v=spf1", StringComparison.OrdinalIgnoreCase))
                {
                    if (verSeen)
                    {
                        return SPFResult.PermError;
                    }

                    verSeen = true;

                    continue;
                }

                Qualifier qualifier;

                if (!Qualifiers.TryGetValue(value[0], out qualifier))
                {
                    qualifier = Qualifier.Pass;
                }
                else
                {
                    value = value.Remove(0, 1);
                }

                if ((value.Equals("a", StringComparison.OrdinalIgnoreCase) || value.StartsWith("a:", StringComparison.OrdinalIgnoreCase)) && !hasAll)
                {
                    currentTermCount++;

                    try
                    {
                        var domain = sendersDomain;

                        if (value.StartsWith("a:", StringComparison.OrdinalIgnoreCase))
                        {
                            domain = value.Substring(2);
                        }

                        var addresses = await GetARecordsAsync(domain, cancellationToken);

                        results.Add((value, addresses.Contains(sendersIP), qualifier));
                    }
                    catch (DnsResponseException ex)
                    {
                        var args = new SPFValidatorErrorEventArgs(ex)
                        {
                            Domain = sendersDomain,
                            Value = value
                        };

                        if (Error is not null)
                        {
                            Error.Invoke(this, args);
                        }

                        return SPFResult.TempError;
                    }
                }
                else if ((value.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) || value.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) && !hasAll)
                {
                    if (IPAddressRange.TryParse(value.Substring(4), out var range))
                    {
                        results.Add((value, range.Contains(sendersIP), qualifier));
                    }
                }
                else if ((value.Equals("mx", StringComparison.OrdinalIgnoreCase) || value.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)) && !hasAll)
                {
                    currentTermCount++;

                    try
                    {
                        var domain = sendersDomain;

                        if (value.StartsWith("mx:", StringComparison.OrdinalIgnoreCase))
                        {
                            domain = value.Substring(3);
                        }

                        var addresses = await GetMXRecordsAsync(domain, cancellationToken);

                        results.Add((value, addresses.Contains(sendersIP), qualifier));
                    }
                    catch (DnsResponseException ex)
                    {
                        var args = new SPFValidatorErrorEventArgs(ex)
                        {
                            Domain = sendersDomain,
                            Value = value
                        };

                        if (Error is not null)
                        {
                            Error.Invoke(this, args);
                        }

                        return SPFResult.TempError;
                    }
                }
                else if (value.Equals("ptr", StringComparison.OrdinalIgnoreCase) && !hasAll)
                {
                    // Shouldn't be used

                    currentTermCount++;
                }
                else if ((value.Equals("exists", StringComparison.OrdinalIgnoreCase) || value.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) && !hasAll)
                {
                    currentTermCount++;

                    try
                    {
                        var domain = sendersDomain;

                        if (value.StartsWith("exists:", StringComparison.OrdinalIgnoreCase))
                        {
                            domain = value.Substring(7);
                        }

                        var addresses = await GetARecordsAsync(domain, cancellationToken);

                        results.Add((value, addresses.Contains(sendersIP), qualifier));
                    }
                    catch (DnsResponseException ex)
                    {
                        var args = new SPFValidatorErrorEventArgs(ex)
                        {
                            Domain = sendersDomain,
                            Value = value
                        };

                        if (Error is not null)
                        {
                            Error.Invoke(this, args);
                        }

                        return SPFResult.TempError;
                    }
                }
                else if (value.StartsWith("include:", StringComparison.OrdinalIgnoreCase) && !hasAll)
                {
                    currentTermCount++;

                    try
                    {
                        var subRecords = await GetTXTRecordsAsync(value.Substring(8), cancellationToken);
                        var subResult = await PerformValidationAsync(subRecords, sendersDomain, sendersIP, currentTermCount, cancellationToken);

                        switch (subResult)
                        {
                            case SPFResult.Pass:
                                results.Add((value, true, qualifier));
                                break;
                            case SPFResult.Fail:
                                results.Add((value, false, qualifier));
                                break;
                            case SPFResult.SoftFail:
                                results.Add((value, false, qualifier));
                                break;
                            case SPFResult.Neutral:
                                results.Add((value, false, qualifier));
                                break;
                            case SPFResult.TempError:
                                return SPFResult.TempError;
                            case SPFResult.PermError:
                                return SPFResult.PermError;
                        }
                    }
                    catch (DnsResponseException ex)
                    {
                        var args = new SPFValidatorErrorEventArgs(ex)
                        {
                            Domain = sendersDomain,
                            Value = value
                        };

                        if (Error is not null)
                        {
                            Error.Invoke(this, args);
                        }

                        return SPFResult.TempError;
                    }
                }
                else if (value.Equals("all", StringComparison.OrdinalIgnoreCase) && !hasAll)
                {
                    results.Add((value, true, qualifier));

                    hasAll = true;
                }
                else if (value.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase) && !hasAll)
                {
                    currentTermCount++;

                    redirect = value.Substring(9);
                }
            }
        }

        foreach (var result in results)
        {
            if (result.Match)
            {
                switch (result.Qualifier)
                {
                    case Qualifier.Pass:
                        return SPFResult.Pass;
                    case Qualifier.Neutral:
                        return SPFResult.Neutral;
                    case Qualifier.SoftFail:
                        return SPFResult.SoftFail;
                    case Qualifier.Fail:
                        return SPFResult.Fail;
                }
            }
        }

        if (!string.IsNullOrEmpty(redirect))
        {
            try
            {
                var subRecords = await GetTXTRecordsAsync(redirect, cancellationToken);
                var subResult = await PerformValidationAsync(subRecords, sendersDomain, sendersIP, currentTermCount, cancellationToken);

                return subResult;
            }
            catch (DnsResponseException ex)
            {
                var args = new SPFValidatorErrorEventArgs(ex)
                {
                    Domain = sendersDomain,
                    Value = $"redirect={redirect}"
                };

                if (Error is not null)
                {
                    Error.Invoke(this, args);
                }

                return SPFResult.TempError;
            }
        }

        return SPFResult.Neutral;
    }

    private async Task<IReadOnlyCollection<string>> GetTXTRecordsAsync(string domain, CancellationToken cancellationToken)
    {
        var results = new List<string>();
        var response = await _dnsClient.QueryAsync(domain, QueryType.TXT, cancellationToken: cancellationToken);
        var records = response.Answers.TxtRecords()
            .ToList();

        foreach (var record in records)
        {
            foreach (var value in record.Text)
            {
                if (value.StartsWith("v=spf1"))
                {
                    results.Add(value);
                }
            }
        }

        return results;
    }

    private async Task<ISet<IPAddress>> GetARecordsAsync(string domain, CancellationToken cancellationToken)
    {
        var results = new HashSet<IPAddress>();
        var hostEntry = await _dnsClient.GetHostEntryAsync(domain);

        if (hostEntry is not null)
        {
            foreach (var address in hostEntry.AddressList)
            {
                results.Add(address);
            }
        }

        return results;
    }

    private async Task<ISet<IPAddress>> GetMXRecordsAsync(string domain, CancellationToken cancellationToken)
    {
        var results = new HashSet<IPAddress>();
        var response = await _dnsClient.QueryAsync(domain, QueryType.MX, cancellationToken: cancellationToken);
        var records = response.Answers.MxRecords()
            .ToList();

        foreach (var record in records)
        {
            var mxAddresses = await GetARecordsAsync(record.Exchange, cancellationToken);

            foreach (var address in mxAddresses)
            {
                results.Add(address);
            }
        }

        return results;
    }

    #endregion

    #region Events

    public event SPFServiceErrorEventHandler? Error;

    #endregion
}
