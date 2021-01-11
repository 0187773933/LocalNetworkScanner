package scanner

import (
	"fmt"
	"net"
	//"io"
	//"bytes"
	//"os"
	"os/exec"
	//"strconv"
	"strings"
	"sort"
	"strconv"
	"runtime"
	default_gateway "github.com/jackpal/gateway"
	//"github.com/mdlayher/arp"
	//"github.com/mdlayher/ethernet"
)

type LocalNetwork struct {
	interfaces map[string]map[string]string
	default_gateway_ip string
	local_ip string
	public_ip string
}

type ArpResult map[string] string

func exec_process( bash_command string , arguments ...string ) ( result string ) {
	command := exec.Command( bash_command , arguments... )
	//command.Env = append( os.Environ() , "DISPLAY=:0.0" )
	out, err := command.Output()
	if err != nil {
		fmt.Println( bash_command )
		fmt.Println( arguments )
		fmt.Println( err )
	}
	result = string( out[:] )
	return
}

// Exec Function Style 2
// CombinedOutput???
func get_net_mask(deviceName string) string {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("ipconfig", "getoption", deviceName, "subnet_mask")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return ""
		}
		nm := strings.Replace(string(out), "\n", "", -1)
		fmt.Printf("netmask=%s OS=%s", nm, runtime.GOOS)
		return nm
	default:
		return ""
	}
	return ""
}

func probe_local_network() LocalNetwork {
	local_network := LocalNetwork{}
	local_network.interfaces = make( map[string]map[string]string )
	interfaces , _ := net.Interfaces()
	//address_info , _ := net.InterfaceAddrs()
	//fmt.Println( address_info )
	for _ , x_interface := range interfaces {
		local_network.interfaces[x_interface.Name] = make( map[string]string )
		addresses , error := x_interface.Addrs()
		if error != nil { continue }
		//fmt.Println( x_interface.HardwareAddr ) // aka the mac address of the interface?
		for _ , address := range addresses {
			var ip net.IP
			var mask net.IPMask
			switch v := address.(type) {
			case *net.IPNet:
				ip = v.IP
				local_network.interfaces[x_interface.Name]["our_ip"] = v.IP.String()
				mask = v.Mask
				//fmt.Println( net.ParseCIDR( local_network.interfaces[x_interface.Name]["our_ip"] ) )
			case *net.IPAddr:
				ip = v.IP
				local_network.interfaces[x_interface.Name]["our_ip"] = v.IP.String()
				mask = ip.DefaultMask()
				//fmt.Println( net.ParseCIDR( local_network.interfaces[x_interface.Name]["our_ip"] ) )
			}
			if ip == nil { continue }
			ip = ip.To4()
			if ip == nil { continue }
			cleanMask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
			fmt.Println( ip , cleanMask )
		}
		//ifi, err := net.InterfaceByName()
		//ifi := *x
	}
	return local_network
}

func nmap_exists() ( result bool ) {
	result = false
	switch runtime.GOOS {
		case "linux":
			cmd := exec.Command( "command" , "-v" , "nmap" )
			err := cmd.Run();
			if err == nil { result = true }
		case "darwin":
			cmd := exec.Command( "command" , "-v" , "nmap" )
			err := cmd.Run();
			if err == nil { result = true }
		case "windows":
			cmd := exec.Command( "where" , "nmap" )
			err := cmd.Run();
			if err == nil { result = true }
	}
	return result
}

func nmap( gateway_ip string ) ( result string ) {
	result = "failed"
	fmt.Printf( "nmapping: %s\n" , gateway_ip )
	switch runtime.GOOS {
		case "linux":
			nmap_command := fmt.Sprintf( "nmap -sn %s/24" , gateway_ip )
			result := exec_process( "/bin/bash" , "-c" , nmap_command )
			return result
		case "darwin":
			nmap_command := fmt.Sprintf( "nmap -sP %s/24" , gateway_ip )
			result := exec_process( "/bin/bash" , "-c" , nmap_command )
			return result
		case "windows":
			nmap_command := fmt.Sprintf( "nmap -sP %s/24" , gateway_ip )
			result := exec_process( `C:\Windows\System32\cmd.exe` , "/c" , nmap_command )
			return result
	}
	return result
}

func arp_exists() ( result bool ) {
	result = false
	switch runtime.GOOS {
		case "linux":
			cmd := exec.Command( "command" , "-v" , "arp" )
			err := cmd.Run();
			if err == nil { result = true }
		case "darwin":
			cmd := exec.Command( "command" , "-v" , "arp" )
			err := cmd.Run();
			if err == nil { result = true }
		case "windows":
			cmd := exec.Command( "where" , "arp" )
			err := cmd.Run();
			if err == nil { result = true }
	}
	return result
}

func arp_interface( interface_name string ) ( result string ) {
	result = "failed"
	fmt.Printf( "arping: %s\n" , interface_name )
	switch runtime.GOOS {
		case "linux":
			result := exec_process( "/bin/bash" , "-c" , fmt.Sprintf( "arp -na -i %s | awk '{{print $2,$4}}'" , interface_name ) )
			return result
		case "darwin":
			result := exec_process( "/bin/bash" , "-c" , fmt.Sprintf( "arp -na -i %s | awk '{{print $2,$4}}'" , interface_name ) )
			return result
		case "windows":
			result := exec_process( `C:\Windows\System32\cmd.exe` , "/c" , "arp -a" )
			return result
	}
	return result
}

func parse_arp_result( default_gateway_ip string , arp_string string ) ( arp_result ArpResult ) {
	arp_result = ArpResult{}
	lines := strings.Split( arp_string , "\n" )
	switch runtime.GOOS {
		case "linux":
			for _ , line := range lines {
				//fmt.Printf( "%s === %s \n" , strconv.Itoa( index ) , line )
				items := strings.Split( line , " " )
				if len( items ) < 2 { continue }
				if items[1] == "(incomplete)" { continue }
				if items[1] == "<incomplete>" { continue }
				ip_address := strings.Split( strings.Split( items[0] , "(" )[1] , ")" )[0]
				arp_result[ip_address] = items[1]
				//fmt.Printf( "%s === %s \n" , ip_address , items[1] )
			}
		case "darwin":
			for _ , line := range lines {
				//fmt.Printf( "%s === %s \n" , strconv.Itoa( index ) , line )
				items := strings.Split( line , " " )
				if len( items ) < 2 { continue }
				if items[1] == "(incomplete)" { continue }
				if items[1] == "<incomplete>" { continue }
				ip_address := strings.Split( strings.Split( items[0] , "(" )[1] , ")" )[0]
				arp_result[ip_address] = items[1]
				//fmt.Printf( "%s === %s \n" , ip_address , items[1] )
			}
		case "windows":
			ip_parts := strings.Split( default_gateway_ip , "." )
			//prefix := strings.Join( ip_parts[ 0 : len( ip_parts ) - 2 ] , "." )
			for _ , line := range lines {
				items_t := strings.Split( line , " " )
				var items []string
				for _ , test := range items_t {
					if test != "" { items = append( items , test ) }
				}
				for item_index , item := range items {
					if strings.Contains( item , "." ) == false { continue }
					item_ip_parts := strings.Split( item , "." )
					if len( item_ip_parts ) < 4 { continue }
					if item_ip_parts[0] == ip_parts[0] {
						if item_ip_parts[1] == ip_parts[1] {
							if item_ip_parts[1] == ip_parts[1] {
								arp_result[item] = items[ item_index + 1 ]
								fmt.Printf( "%s === %s \n" , item , items[ item_index + 1 ] )
							}
						}
					}
				}
			}
	}
	return

}

func sort_local_network( arp_result ArpResult ) ( network_map [][2]string ) {
	//arp_result["192.168.1.52"] = "b8:27:eb:52:a7:6b"
	var ip_address_ends []int
	for key := range arp_result {
		ip_address_parts := strings.Split( key , "." )
		i , _ := strconv.Atoi( ip_address_parts[ len( ip_address_parts ) - 1 ] )
		ip_address_ends = append( ip_address_ends , i )
	}
	sort.Ints( ip_address_ends )
	for _ , key := range ip_address_ends {
		var new_item [2]string
		new_item[0] = fmt.Sprintf( "192.168.1.%d" , key )
		new_item[1] = arp_result[ fmt.Sprintf( "192.168.1.%d" , key ) ]
		//fmt.Println( new_item )
		network_map = append( network_map , new_item )
		//fmt.Println( fmt.Sprintf( "192.168.1.%d ===" , key ) , network_map[ fmt.Sprintf( "192.168.1.%d" , key ) ] )
	}
	return
}

// Delete ARP Cache
// https://theknowledgehound.home.blog/2020/03/13/netsh-configuring-network-settings-from-the-command-line/
// Windows == netsh interface ip delete arpcache

func get_default_interface_name() ( result string ) {
	result = "failed"
	switch runtime.GOOS {
		case "linux":
			output := exec_process( "/bin/bash" , "-c" , "ip -o -4 route show to default | awk '{print $5}'" )
			lines := strings.Split( output , "\n" )
			result = lines[ len( lines ) - 2 ]
		case "darwin":
			output := exec_process( "/bin/bash" , "-c" , "route get google.com | grep interface | tail -1 | awk '{print $2}'" )
			lines := strings.Split( output , "\n" )
			result = lines[ len( lines ) - 2 ]
		case "windows":
			//output := exec_process( `C:\Windows\System32\cmd.exe` , "/c" , "netsh interface show interface | findstr \"Connected\"" )
			output := exec_process( `C:\Windows\System32\cmd.exe` , "/c" , "netsh interface show interface" )
			lines := strings.Split( output , "\n" )
			for _ , line := range lines {
				if strings.Contains( line , "Connected" ) == false { continue }
				if strings.Contains( line , "Loopback" ) { continue }
				items := strings.Split( line , " " )
				result = items[ len( items ) - 1 ]
			}
	}
	return
}


//C:\Windows\System32\cmd.exe /c for /F "skip=3 tokens=3*" %G in ('netsh interface show interface') do echo %%H

func print_network( local_network [][2]string ) {
	for index := range local_network {
		fmt.Printf( "%d === %s === %s\n" , index , local_network[index][0] , local_network[index][1] )
	}
}

func ScanLocalNetwork() ( local_network [][2]string ) {
	fmt.Printf( "nmap exists === %t\n" , nmap_exists() )
	fmt.Printf( "arp exists === %t\n" , arp_exists() )
	interface_name := get_default_interface_name()
	fmt.Printf( "Default Interface Name === %s\n" , interface_name )
	default_gateway_ip , _ := default_gateway.DiscoverGateway()
	fmt.Printf( "Default Gateway IP === %s\n" , default_gateway_ip.String() )
	nmap( default_gateway_ip.String() )
	arp_result := parse_arp_result( default_gateway_ip.String() , arp_interface( interface_name ) )
	local_network = sort_local_network( arp_result )

	return
}

func PrintLocalNetwork() {
	net := ScanLocalNetwork()
	print_network( net )
}

func GetIPAddressFromMacAddress( mac_address string ) ( ip_address string ) {
	fmt.Printf( "nmap exists === %t\n" , nmap_exists() )
	fmt.Printf( "arp exists === %t\n" , arp_exists() )
	interface_name := get_default_interface_name()
	fmt.Printf( "Default Interface Name === %s\n" , interface_name )
	default_gateway_ip , _ := default_gateway.DiscoverGateway()
	fmt.Printf( "Default Gateway IP === %s\n" , default_gateway_ip.String() )
	nmap( default_gateway_ip.String() )
	arp_result := parse_arp_result( default_gateway_ip.String() , arp_interface( interface_name ) )
	local_network := sort_local_network( arp_result )
	print_network( local_network )
	for index := range local_network {
		if local_network[ index ][ 1 ] == mac_address {
			ip_address = local_network[ index ][ 0 ]
		}
	}
	return
}