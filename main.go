package main

import (
	localnetwork "localnetwork"
)

func main() {
	fmt.Println( GetIPAddressFromMacAddress( strings.Replace( strings.ToLower( "2C-64-1F-25-6B-3C" ) , "-" , ":" , -1 ) ) )
}