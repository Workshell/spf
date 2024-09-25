using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Workshell.SPF;

public sealed class SPFValidatorErrorEventArgs : EventArgs
{
    public SPFValidatorErrorEventArgs(Exception exception)
    {
        Exception = exception;
    }

    #region Properties

    public Exception Exception { get; }
    public string? Domain { get; internal set; }
    public string? Value { get; internal set; }

    #endregion
}
