# Local Network Scanner

```
package main

import (
	"fmt"
	"strings"
	localnetwork "github.com/0187773933/LocalNetworkScanner"
)

func main() {
	fmt.Println( localnetwork.GetIPAddressFromMacAddress( strings.Replace( strings.ToLower( "2C-64-1F-25-6B-3C" ) , "-" , ":" , -1 ) ) )
}
```