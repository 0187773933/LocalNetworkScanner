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
		fmt.Sprintf( "%s\n" , err )
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

func nmap( gateway_ip string ) ( result string ) {
	result = "failed"
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

func arp_interface( interface_name string ) ( result string ) {
	result = "failed"
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

func parse_arp_result( arp_string string ) ( arp_result ArpResult ) {
	arp_result = ArpResult{}
	lines := strings.Split( arp_string , "\n" )
	for _ , line := range lines {
		//fmt.Printf( "%s === %s \n" , strconv.Itoa( index ) , line )
		items := strings.Split( line , " " )
		if len( items ) < 2 { continue }
		if items[1] == "(incomplete)" { continue }
		ip_address := strings.Split( strings.Split( items[0] , "(" )[1] , ")" )[0]
		arp_result[items[1]] = ip_address
		//fmt.Printf( "%s === %s \n" , ip_address , items[1] )
	}
	return arp_result
}

func GetIPAddressFromMacAddress( mac_address string ) ( ip_address string ) {
	default_gateway_ip , _ := default_gateway.DiscoverGateway()
	nmap( default_gateway_ip.String() )
	arp_result := parse_arp_result( arp_interface("en0") )
	ip_address = arp_result[mac_address]
	return
}