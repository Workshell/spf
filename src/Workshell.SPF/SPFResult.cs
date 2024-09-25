using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Workshell.SPF;

public enum SPFResult
{
    None = 0,
    Neutral = 1,
    Pass = 2,
    Fail = 3,
    SoftFail = 4,
    TempError = 5,
    PermError = 6
}
